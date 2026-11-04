package decompengine.chatgpt

import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout

@Timeout(5)
class ChatGptAuthLifetimeTest {
    private fun commit(state: ChatGptAuthCommitState = ChatGptAuthCommitState.DURABLE) = object : ChatGptAuthCommit() {
        override val state = state
        override val account: ChatGptPlanAccount? = null
    }

    private class SlowPhase(val advance: Long = 31_000_000_000) {
        val now = AtomicLong()
        val call = AtomicInteger()
        val armed = AtomicBoolean()
        val life = ChatGptAuthLifetime.start(clock = now::get, parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long {
                if (armed.get() && call.incrementAndGet() == 3) now.addAndGet(advance)
                return 200_000_000_000
            }
        })
        val phase = life.phaseOperation(ChatGptAuthPhase.EXCHANGE)
        fun arm() { call.set(0); armed.set(true) }
    }
    @Test fun phaseClockMustChargeParentCallbackBeforeReturningPhaseAuthority() {
        val x = SlowPhase()
        try {
            // StoreOperation cancellation invokes parent once; its clock invokes parent again.
            x.call.set(1); x.armed.set(true)
            assertFails { x.phase.check() }
        } finally { x.life.settle() }
    }
    @Test fun slowParentMustNotGrantDispatchBeyondExchangeDeadline() {
        val x = SlowPhase()
        try {
            x.arm()
            val granted = x.life.claimDispatch()
            assertEquals(31_000_000_000, x.now.get())
            assertFalse(granted, "dispatch admitted after original exchange phase expired")
        } finally { x.life.settle() }
    }
    @Test fun slowParentMustNotGrantPublicationBeyondExchangeDeadline() {
        val x = SlowPhase()
        var entered = false
        try {
            x.arm(); entered = x.life.publication().enterCommit()
            assertEquals(31_000_000_000, x.now.get())
            assertFalse(entered, "publication admitted after original exchange phase expired")
        } finally {
            if (entered) x.life.publication().complete(commit())
            x.life.settle()
        }
    }
    private fun cancelInsideParent(publication: Boolean) {
        val flag = AtomicBoolean()
        val armed = AtomicBoolean()
        val calls = AtomicInteger()
        val life = ChatGptAuthLifetime.start(cancellation = object : ChatGptAuthCancellation() {
            override fun isCancelled() = flag.get()
        }, parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long {
                if (armed.get() && calls.incrementAndGet() == 3) flag.set(true)
                return 100_000_000_000
            }
        })
        var entered = false
        try {
            life.phaseOperation(ChatGptAuthPhase.EXCHANGE)
            armed.set(true)
            val granted = if (publication) life.publication().enterCommit().also { entered = it } else life.claimDispatch()
            assertTrue(flag.get())
            assertFalse(granted, "authority granted after external cancellation became visible inside parent callback")
        } finally {
            if (entered) life.publication().complete(commit())
            life.settle()
        }
    }
    @Test fun dispatchMustRecheckCancellationAfterParentCallback() = cancelInsideParent(false)
    @Test fun publicationMustRecheckCancellationAfterParentCallback() = cancelInsideParent(true)

    @Test fun parentCallbackJustBeforePhaseDeadlinePreservesAuthority() {
        for (publication in listOf(false, true)) {
            val x = SlowPhase(29_999_999_999L)
            var entered = false
            try {
                x.arm()
                val allowed = if (publication) x.life.publication().enterCommit().also { entered = it } else x.life.claimDispatch()
                assertEquals(29_999_999_999L, x.now.get())
                assertTrue(allowed)
            } finally {
                if (entered) x.life.publication().complete(commit())
                assertEquals(ChatGptAuthSettlement.SETTLED, x.life.settle())
            }
        }
    }

    @Test fun originalDeadlineIncludesInitializationAndNeverRestarts() {
        val now = AtomicLong(100)
        val life = ChatGptAuthLifetime.start(clock = now::get)
        now.addAndGet(299_000_000_000)
        assertEquals(1_000_000_000, life.remainingNanos())
        val phase = life.phaseOperation(ChatGptAuthPhase.EXCHANGE)
        assertEquals(1_000_000_000, phase.remainingNanos())
        now.addAndGet(1_000_000_000)
        assertFails { phase.check() }
        assertFalse(life.publication().enterCommit())
        now.set(100) // expiration is sticky even if a broken clock moves backwards
        assertFails { life.check() }
        assertEquals(ChatGptAuthSettlement.SETTLED, life.settle())
    }

    @Test fun phasesAreOnceOnlyAndClippedToOriginalParent() {
        val now = AtomicLong()
        val parent = AtomicLong(4_000_000_000)
        val life = ChatGptAuthLifetime.start(parent = object : ChatGptAuthParent() {
            override fun remainingNanos() = parent.get()
        }, clock = now::get)
        for (name in ChatGptAuthPhase.entries) {
            val phase = life.phaseOperation(name)
            assertSame(phase, life.phaseOperation(name))
            assertEquals(4_000_000_000, phase.remainingNanos())
        }
        parent.set(10)
        assertEquals(10, life.remainingNanos())
        for (phase in ChatGptAuthPhase.entries) assertEquals(10, life.phaseOperation(phase).remainingNanos())
        parent.set(0)
        assertFalse(life.claimDispatch())
        parent.set(4_000_000_000)
        assertFails { life.check() }
        life.settle()
    }

    @Test fun everyPhaseHasThirtySecondMaximumWithoutRenewal() {
        val now = AtomicLong()
        val life = ChatGptAuthLifetime.start(clock = now::get)
        for (phase in ChatGptAuthPhase.entries) assertEquals(30_000_000_000, life.phaseOperation(phase).remainingNanos())
        now.set(30_000_000_000)
        for (phase in ChatGptAuthPhase.entries) assertFails { life.phaseOperation(phase).check() }
        life.settle()
    }

    @Test fun parentTimeSpentDuringPhaseCreationCannotExtendBudget() {
        val now = AtomicLong()
        val life = ChatGptAuthLifetime.start(clock = now::get, parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long { now.addAndGet(100); return 500 }
        })
        val op = life.phaseOperation(ChatGptAuthPhase.PREPARATION)
        now.addAndGet(500)
        assertFails { op.check() }
        life.settle()
    }

    @Test fun timeSpentReadingParentIsChargedBeforeReturningAuthority() {
        val now = AtomicLong()
        val life = ChatGptAuthLifetime.start(Duration.ofSeconds(1), clock = now::get, parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long { now.set(1_000_000_000); return 5_000_000_000 }
        })
        try { assertEquals(ChatGptAuthFailure.TIMEOUT, assertFailsWith<ChatGptAuthException> { life.check() }.failure) }
        finally { life.settle() }
    }

    @Test fun budgetsRejectOverflowAndClockSupportsSignedWrap() {
        for (duration in listOf(Duration.ZERO, Duration.ofNanos(-1), Duration.ofMinutes(6), Duration.ofSeconds(Long.MAX_VALUE))) {
            assertFailsWith<IllegalArgumentException> { ChatGptAuthLifetime.start(duration) }
        }
        val now = AtomicLong(Long.MAX_VALUE - 5)
        val life = ChatGptAuthLifetime.start(Duration.ofNanos(20), clock = now::get)
        now.addAndGet(10)
        assertEquals(10, life.remainingNanos())
        now.addAndGet(10)
        assertEquals(ChatGptAuthFailure.TIMEOUT, assertFailsWith<ChatGptAuthException> { life.check() }.failure)
        life.settle()
    }

    @Test fun cancellationWinsBeforePublicationAndDispatch() {
        val life = ChatGptAuthLifetime.start()
        assertEquals(ChatGptAuthCancelResult.CANCELLED, life.cancel())
        assertFalse(life.publication().enterCommit())
        assertFalse(life.claimDispatch())
        assertNull(life.commitOutcome())
        assertFails { life.publication().complete(commit()) }
        assertEquals(ChatGptAuthSettlement.SETTLED, life.settle())
    }

    @Test fun publicationWinsThenCancellationReportsInProgressUntilDurableOrUnknown() {
        for (state in ChatGptAuthCommitState.entries) {
            val life = ChatGptAuthLifetime.start()
            assertTrue(life.publication().enterCommit())
            assertFalse(life.publication().enterCommit())
            assertEquals(ChatGptAuthCancelResult.COMMIT_IN_PROGRESS, life.cancel())
            assertEquals(ChatGptAuthSettlement.UNSETTLED, life.settle())
            val outcome = commit(state)
            life.publication().complete(outcome)
            assertSame(outcome, life.commitOutcome())
            assertEquals(state, life.commitOutcome()!!.state)
            assertEquals(ChatGptAuthCancelResult.ALREADY_SETTLED, life.cancel())
            assertFails { life.publication().complete(commit()) }
            assertEquals(ChatGptAuthSettlement.SETTLED, life.settle())
        }
    }

    @Test fun concurrentPublicationVersusCancelHasExactlyOneAuthorityWinner() {
        repeat(100) {
            val life = ChatGptAuthLifetime.start()
            val barrier = CountDownLatch(1)
            var entered = false
            var cancelled: ChatGptAuthCancelResult? = null
            val a = Thread({ barrier.await(); entered = life.publication().enterCommit() }, "chatgpt-test-gate")
            val b = Thread({ barrier.await(); cancelled = life.cancel() }, "chatgpt-test-cancel")
            try {
                a.start(); b.start(); barrier.countDown()
                a.join(1000); b.join(1000)
                assertFalse(a.isAlive); assertFalse(b.isAlive)
                if (entered) {
                    assertEquals(ChatGptAuthCancelResult.COMMIT_IN_PROGRESS, cancelled)
                    life.publication().complete(commit())
                } else assertEquals(ChatGptAuthCancelResult.CANCELLED, cancelled)
                assertFalse(life.claimDispatch())
            } finally { barrier.countDown(); a.join(1000); b.join(1000); life.settle() }
        }
    }

    @Test fun oneDispatchClaimSurvivesRepeatedSerializationAndRaces() {
        val life = ChatGptAuthLifetime.start()
        val wins = AtomicInteger()
        val threads = List(8) { Thread({ if (life.claimDispatch()) wins.incrementAndGet() }, "chatgpt-test-dispatch") }
        try {
            threads.forEach(Thread::start); threads.forEach { it.join(1000) }
            assertTrue(threads.none(Thread::isAlive)); assertEquals(1, wins.get())
            assertTrue(life.publication().enterCommit())
            life.publication().complete(commit())
            assertFalse(life.claimDispatch())
        } finally { threads.forEach { it.join(1000) }; life.settle() }
    }

    @Test fun cleanupCallbackObservesResultFenceBeforeAnyResourceAction() {
        val life = ChatGptAuthLifetime.start()
        val ack = CountDownLatch(1)
        val violation = AtomicInteger()
        life.own(object : ChatGptAuthResource() {
            override fun stopAndAwait(): Boolean {
                if (life.publication().enterCommit() || life.claimDispatch()) violation.incrementAndGet()
                ack.countDown(); return true
            }
        })
        life.cancel()
        assertFails { life.check() }
        assertTrue(ack.await(1, TimeUnit.SECONDS))
        settleEventually(life)
        assertEquals(0, violation.get())
    }

    @Test fun expiredExchangeCannotPublishWhileInteractiveDeadlineRemains() {
        val now = AtomicLong()
        val life = ChatGptAuthLifetime.start(clock = now::get)
        life.phaseOperation(ChatGptAuthPhase.EXCHANGE)
        now.set(30_000_000_000)
        assertTrue(life.remainingNanos() > 0)
        assertFalse(life.publication().enterCommit())
        assertFalse(life.claimDispatch())
        life.settle()
    }

    @Test fun expiredExchangeCannotSubmitDespiteRemainingInteractiveTime() {
        val now = AtomicLong()
        val life = ChatGptAuthLifetime.start(clock = now::get)
        life.phaseOperation(ChatGptAuthPhase.EXCHANGE)
        now.set(30_000_000_000)
        assertFalse(life.claimDispatch())
        assertFalse(life.publication().enterCommit())
        life.settle()
    }

    @Test fun cancellationAfterSubmissionAndLateWorkerResultCannotPublish() {
        val life = ChatGptAuthLifetime.start()
        val submitted = CountDownLatch(1)
        val release = CountDownLatch(1)
        val publications = AtomicInteger()
        val worker = Thread({
            submitted.countDown(); release.await()
            if (life.publication().enterCommit()) publications.incrementAndGet()
        }, "chatgpt-test-late-adapter")
        life.own(object : ChatGptAuthResource() {
            override fun stopAndAwait(): Boolean { worker.join(); return !worker.isAlive }
        })
        try {
            assertTrue(life.claimDispatch()); worker.start()
            assertTrue(submitted.await(1, TimeUnit.SECONDS))
            assertEquals(ChatGptAuthSettlement.UNSETTLED, life.settle())
            assertTrue(worker.isAlive) // authority revoked; physical callback intentionally not terminated
            assertFalse(life.claimDispatch())
        } finally {
            release.countDown(); worker.join(1000); assertFalse(worker.isAlive)
            settleEventually(life)
        }
        assertEquals(0, publications.get())
    }

    @Test fun uncooperativeCleanupIsRevokedNotKilledAndExplicitlyReleasedAndJoined() {
        val life = ChatGptAuthLifetime.start()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        var cleanupThread: Thread? = null
        life.own(object : ChatGptAuthResource() {
            override fun stopAndAwait(): Boolean {
                cleanupThread = Thread.currentThread(); entered.countDown(); release.await(); return true
            }
        })
        try {
            val start = System.nanoTime()
            assertEquals(ChatGptAuthSettlement.UNSETTLED, life.settle())
            assertTrue(System.nanoTime() - start < 1_000_000_000)
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertTrue(cleanupThread!!.isAlive)
            assertFalse(life.publication().enterCommit())
            assertFalse(life.claimDispatch())
        } finally {
            release.countDown(); cleanupThread?.join(1000)
            assertFalse(cleanupThread?.isAlive == true)
            settleEventually(life)
        }
    }

    @Test fun failedAndNegativeAcknowledgementsNeverClaimSettlementOrLeakCauses() {
        for (throws in listOf(false, true)) {
            val life = ChatGptAuthLifetime.start()
            val done = CountDownLatch(1)
            life.own(object : ChatGptAuthResource() {
                override fun stopAndAwait(): Boolean {
                    done.countDown()
                    if (throws) throw IllegalStateException("CANARY-cleanup-secret")
                    return false
                }
            })
            assertEquals(ChatGptAuthSettlement.UNSETTLED, life.settle())
            assertTrue(done.await(1, TimeUnit.SECONDS))
            assertEquals(ChatGptAuthSettlement.UNSETTLED, life.settle())
            assertFalse(life.toString().contains("CANARY"))
        }
    }

    @Test fun resourceRegistryIsBoundedUniqueAndClosedAfterFence() {
        val life = ChatGptAuthLifetime.start()
        val resource = object : ChatGptAuthResource() { override fun stopAndAwait() = true }
        life.own(resource)
        assertFails { life.own(resource) }
        repeat(15) { life.own(object : ChatGptAuthResource() { override fun stopAndAwait() = true }) }
        assertEquals(ChatGptAuthFailure.RESOURCE_LIMIT, assertFailsWith<ChatGptAuthException> {
            life.own(object : ChatGptAuthResource() { override fun stopAndAwait() = true })
        }.failure)
        life.cancel()
        assertFails { life.own(resource) }
        settleEventually(life)
    }

    @Test fun externalCancellationAndDependencyFailuresAreStickyAndRedacted() {
        val flag = AtomicInteger()
        val life = ChatGptAuthLifetime.start(cancellation = object : ChatGptAuthCancellation() {
            override fun isCancelled() = flag.get() != 0
        })
        life.check(); flag.set(1); assertFails { life.check() }; flag.set(0)
        assertFalse(life.publication().enterCommit()); life.settle()
        val broken = ChatGptAuthLifetime.start(parent = object : ChatGptAuthParent() {
            override fun remainingNanos(): Long = throw IllegalArgumentException("CANARY-state-code-hint")
        })
        val e = assertFailsWith<ChatGptAuthException> { broken.check() }
        assertEquals(ChatGptAuthFailure.DEPENDENCY_FAILED, e.failure)
        assertNull(e.cause); assertTrue(e.suppressed.isEmpty()); assertFalse(e.toString().contains("CANARY"))
        broken.settle()
    }

    companion object {
        internal fun settleEventually(life: ChatGptAuthLifetime) {
            val end = System.nanoTime() + 1_000_000_000
            while (life.settle() != ChatGptAuthSettlement.SETTLED && System.nanoTime() < end) Thread.sleep(1)
            assertEquals(ChatGptAuthSettlement.SETTLED, life.settle())
        }
    }
}
