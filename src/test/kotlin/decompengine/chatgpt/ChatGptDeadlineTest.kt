package decompengine.chatgpt

import kotlin.test.*
import java.lang.reflect.Modifier

class ChatGptDeadlineTest {
    @Test fun constructorsArePrivateAndAuthorityIsFinal() {
        for (type in listOf(ChatGptDeadline::class.java, ChatGptDeadlineClock::class.java)) {
            assertTrue(Modifier.isFinal(type.modifiers))
            assertTrue(type.declaredConstructors.filterNot { it.isSynthetic }.all { Modifier.isPrivate(it.modifiers) })
        }
    }
    @Test fun rootPhaseHttpIntersectWithoutRenewal() {
        val c = ChatGptDeadlineClock.controlled()
        val root = ChatGptDeadline.start(c, 100)
        c.advanceNanos(80)
        val phase = root.cap(50); val http = phase.cap(40)
        assertTrue(http.isWithin(root)); assertTrue(http.isWithin(phase))
        assertEquals(20, http.remainingNanos())
        c.advanceNanos(20)
        assertEquals(0, http.remainingNanos()); assertEquals(0, root.remainingNanos())
    }
    @Test fun capturedAdmissionChargesGetterAndRejectsNewerParentOrigin() {
        val c = ChatGptDeadlineClock.controlled(); val parent = ChatGptDeadline.start(c, 1_000)
        val entry = c.readNanos(); c.advanceNanos(90)
        assertEquals(10, parent.capAt(entry, 100).remainingNanos())
        assertEquals(0, ChatGptDeadline.start(c, 1_000).capAt(entry, 100).remainingNanos())
    }
    @Test fun signedWrapUsesElapsedSubtraction() {
        val c = ChatGptDeadlineClock.controlled(Long.MAX_VALUE - 40)
        val d = ChatGptDeadline.start(c, 100)
        c.advanceNanos(75); assertEquals(25, d.remainingNanos())
        c.advanceNanos(25); assertEquals(0, d.remainingNanos())
    }
    @Test fun backwardAndFaultAreSticky() {
        for (delta in listOf(-1L, 1_200_000_000_001L)) {
            val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 100)
            c.advanceNanos(delta); assertEquals(0, d.remainingNanos())
            c.advanceNanos(0); assertEquals(0, d.remainingNanos())
        }
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 100)
        c.invalidate(); assertEquals(0, d.remainingNanos())
    }
    @Test fun tighteningIsAnchoredBeforeHelperAndNeverExtends() {
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 1_000)
        val child = d.cap(900); val before = c.readNanos(); c.advanceNanos(90)
        d.tightenFrom(before, 100); assertEquals(10, child.remainingNanos())
        d.tightenFrom(c.readNanos(), 1_000); assertEquals(10, child.remainingNanos())
        c.advanceNanos(10); assertEquals(0, child.remainingNanos())
        d.tightenFrom(before, Long.MAX_VALUE); assertEquals(0, d.remainingNanos())
    }
    @Test fun detachRetainsOriginalOriginAndCutoffButNotLaterCancellationTightening() {
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 1_000)
        c.advanceNanos(800); val fetch = d.detach().cap(500)
        assertFalse(fetch.isWithin(d)); assertSame(c, fetch.clock)
        d.tightenFrom(c.readNanos(), 0); assertEquals(200, fetch.remainingNanos())
        c.advanceNanos(200); assertEquals(0, fetch.remainingNanos())
    }
    @Test fun independentDomainsCannotMintChildrenOfEachOther() {
        val a = ChatGptDeadline.start(ChatGptDeadlineClock.controlled(), 100)
        val b = ChatGptDeadline.start(ChatGptDeadlineClock.controlled(), 100)
        assertFalse(a.isWithin(b)); assertFalse(b.isWithin(a))
        assertFalse(a.isWithin(a.cap(10)))
    }
    @Test fun cleanupNeverGrantsAbsentExpiredOrZeroAuthority() {
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 100)
        assertEquals(0, ChatGptCleanupWindow(null, 250_000_000L).remainingNanos())
        val zero = ChatGptCleanupWindow(d, 0); assertEquals(0, zero.remainingNanos())
        c.advanceNanos(100)
        assertEquals(0, ChatGptCleanupWindow(d, 250_000_000L).remainingNanos())
        assertEquals(0, zero.remainingNanos())
    }
    @Test fun cleanupRechecksCurrentOriginalTimeAndDoesNotRenew() {
        val c = ChatGptDeadlineClock.controlled(); val d = ChatGptDeadline.start(c, 1_000_000_000L)
        val w = ChatGptCleanupWindow(d, 250_000_000L)
        c.advanceNanos(200_000_000L); assertTrue(w.remainingNanos() in 1..50_000_000L)
        c.advanceNanos(50_000_000L); assertEquals(0, w.remainingNanos())
        assertEquals(0, w.remainingNanos())
    }
    @Test fun cancellationLatchDoesNotInventCleanupTimeOrUncancel() {
        val f = ChatGptOperationFence(); assertFalse(f.isCancelled())
        f.cancel(); f.cancel(); assertTrue(f.isCancelled())
    }
    @Test fun fullDomainAndOriginCapsDoNotRestartOrDetach() {
        val max = 1_200_000_000_000L
        val c = ChatGptDeadlineClock.controlled(Long.MAX_VALUE - 10)
        val root = ChatGptDeadline.start(c, max)
        assertFailsWith<IllegalArgumentException> { ChatGptDeadline.start(c, max + 1) }
        assertFailsWith<IllegalArgumentException> { root.capFromOrigin(max + 1) }
        assertFailsWith<IllegalArgumentException> { root.capFromOrigin(-1) }
        assertEquals(0, root.capFromOrigin(0).remainingNanos())
        val full = root.capFromOrigin(max)
        c.advanceNanos(600_000_000_000L); assertEquals(600_000_000_000L, full.remainingNanos())
        c.advanceNanos(200_000_000_000L); assertEquals(400_000_000_000L, full.remainingNanos())
        val smaller = full.capFromOrigin(900_000_000_000L)
        assertTrue(smaller.isWithin(root)); assertEquals(100_000_000_000L, smaller.remainingNanos())
        assertEquals(100_000_000_000L, smaller.capFromOrigin(max).remainingNanos())
        root.tightenFrom(c.readNanos(), 10)
        assertEquals(10, smaller.remainingNanos())
        assertEquals(10, full.capFromOrigin(max).remainingNanos())
        c.advanceNanos(400_000_000_000L); assertEquals(0, full.remainingNanos())
        c.advanceNanos(1); assertEquals(0, root.capFromOrigin(max).remainingNanos())
    }
    @Test fun backwardsObservationAndCumulativeOverflowCannotReviveRoot() {
        for (elapsed in listOf(-1L, 1_200_000_000_001L)) {
            val c = ChatGptDeadlineClock.controlled(); val root = ChatGptDeadline.start(c, 1_200_000_000_000L)
            // Reflection injects a hostile observation, without weakening the controlled API.
            val ticks = ChatGptDeadlineClock::class.java.getDeclaredField("ticks").apply { isAccessible = true }
                .get(c) as java.util.concurrent.atomic.AtomicLong
            ticks.set(elapsed); assertEquals(0, root.remainingNanos())
            ticks.set(0); root.tightenFrom(0, Long.MAX_VALUE)
            assertEquals(0, root.capFromOrigin(1_200_000_000_000L).remainingNanos())
        }
        val c = ChatGptDeadlineClock.controlled(); val root = ChatGptDeadline.start(c, 1_200_000_000_000L)
        val ticks = ChatGptDeadlineClock::class.java.getDeclaredField("ticks").apply { isAccessible = true }
            .get(c) as java.util.concurrent.atomic.AtomicLong
        c.advanceNanos(800_000_000_000L); assertEquals(400_000_000_000L, root.remainingNanos())
        ticks.set(700_000_000_000L); assertEquals(400_000_000_000L, root.remainingNanos())
        ticks.set(800_000_000_000L); c.advanceNanos(400_000_000_001L)
        assertEquals(0, root.remainingNanos()); ticks.set(0); assertEquals(0, root.remainingNanos())
    }
}
