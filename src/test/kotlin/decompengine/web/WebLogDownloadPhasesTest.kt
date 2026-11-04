package decompengine.web

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebLogDownloadPhasesTest {
    private val base = "web-capacity-summary successful=3 client_errors=0 server_errors=0 closed_without_response=0 " +
        "overload_responses=0 overload_closed=0 header_deadline_closures=0 request_deadline_closures=0 header_limit_rejections=0"

    @Test fun `no entrant golden never samples the clock`() {
        val suffix = WebLogDownloadPhases { error("no clock for empty record") }.summarySuffix()
        assertEquals(" lp_v=1 lp_entries=0 lp_present=0 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=0 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=0 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 " +
            "lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=0", suffix)
    }

    @Test fun `normal G1 golden uses ten or fewer clock reads`() {
        val values = longArrayOf(0, 1, 5, 9, 12, 13, 14, 14, 14, 900).map { it * 1_000_000L }.iterator()
        val reads = AtomicInteger()
        val phases = WebLogDownloadPhases { reads.incrementAndGet(); values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.CAPTURE_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.BYTES_READY)
        owner.mark(WebLogDownloadPhases.Phase.HEADERS_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.BODY_CLOSED)
        owner.mark(WebLogDownloadPhases.Phase.EXCHANGE_CLOSED)
        owner.exit(true)
        assertEquals(" lp_v=1 lp_entries=1 lp_present=1023 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=1 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=1 lp_read_ms=5 lp_capture_ms=9 lp_bytes_ms=12 lp_headers_ms=13 lp_body_ms=14 " +
            "lp_exchange_ms=14 lp_exit_ms=14 lp_snapshot_ms=900", phases.summarySuffix())
        assertEquals(10, reads.get())
        phases.summarySuffix()
        assertEquals(10, reads.get())
    }

    @Test fun `second entrant is saturated and snapshot is capped`() {
        val values = listOf(0L, 2_000_000L, 70_000_000_000L).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        assertEquals(null, phases.enter())
        val frozen = " lp_v=1 lp_entries=2 lp_present=515 lp_saturated=512 lp_invalid=0 lp_incomplete=1 lp_terminal=0 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=2 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 " +
            "lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=60000"
        assertEquals(frozen, phases.summarySuffix())
        owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
        assertEquals(frozen, phases.summarySuffix())
    }

    @Test fun `clock regression is sticky and preserves unwound terminal`() {
        val values = listOf(0L, 1_000_000L, 0L).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
        owner.exit(false)
        assertEquals(" lp_v=1 lp_entries=1 lp_present=0 lp_saturated=0 lp_invalid=1 lp_incomplete=0 lp_terminal=2 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=0 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 " +
            "lp_exchange_ms=0 lp_exit_ms=0 lp_snapshot_ms=0", phases.summarySuffix())
    }

    @Test fun `valid unwound exit includes branch-exit bit`() {
        val values = listOf(0L, 4_000_000L, 5_000_000L).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        phases.enter()!!.exit(false)
        assertEquals(" lp_v=1 lp_entries=1 lp_present=769 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=2 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=0 lp_read_ms=0 lp_capture_ms=0 lp_bytes_ms=0 lp_headers_ms=0 lp_body_ms=0 " +
            "lp_exchange_ms=0 lp_exit_ms=4 lp_snapshot_ms=5", phases.summarySuffix())
    }

    @Test fun `header failure unwound G5 golden preserves the explicit close slot`() {
        val values = listOf(0L, 1L, 5L, 9L, 12L, 14L, 14L, 20L).map { it * 1_000_000L }.iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.CAPTURE_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.BYTES_READY)
        owner.mark(WebLogDownloadPhases.Phase.EXCHANGE_CLOSED)
        owner.exit(false)
        assertEquals(" lp_v=1 lp_entries=1 lp_present=927 lp_saturated=0 lp_invalid=0 lp_incomplete=0 lp_terminal=2 lp_cap_ms=60000 " +
            "lp_enter_ms=0 lp_validated_ms=1 lp_read_ms=5 lp_capture_ms=9 lp_bytes_ms=12 lp_headers_ms=0 lp_body_ms=0 " +
            "lp_exchange_ms=14 lp_exit_ms=14 lp_snapshot_ms=20", phases.summarySuffix())
    }

    @Test fun `duplicate mark and exit do not resample or overwrite first stamp`() {
        val values = listOf(10L, 20L, 30L, 40L).iterator()
        val reads = AtomicInteger()
        val phases = WebLogDownloadPhases { reads.incrementAndGet(); values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.exit(false)
        owner.exit(true)
        assertEquals(3, reads.get())
        assertTrue(phases.summarySuffix().contains("lp_validated_ms=0"))
        assertTrue(phases.summarySuffix().contains("lp_exit_ms=0"))
    }

    @Test fun `fault latch survives a suppressed invalid-state publication at freeze`() {
        var reads = 0
        val phases = WebLogDownloadPhases {
            when (++reads) {
                1 -> 0L
                2 -> throw AssertionError("diagnostic clock fault")
                else -> 1_000_000L
            }
        }
        val owner = phases.enter()!!
        @Suppress("UNCHECKED_CAST")
        val published = WebLogDownloadPhases::class.java.getDeclaredField("published")
            .apply { isAccessible = true }.get(phases) as java.util.concurrent.atomic.AtomicReference<Any?>
        val validBeforeFault = checkNotNull(published.get())
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        assertEquals(2, reads)
        // Reproduce the publication-boundary state of the old two-check race, without a new product seam.
        // This models suppressed invalid publication; it does not claim to schedule that interleaving.
        published.set(validBeforeFault)
        val suffix = phases.summarySuffix()
        assertTrue(suffix.contains("lp_entries=1 lp_present=0 lp_saturated=0 lp_invalid=1 lp_incomplete=1 lp_terminal=0"), suffix)
        assertTrue(suffix.substringAfter("lp_cap_ms=60000 ").split(' ').all { it.endsWith("=0") }, suffix)
        assertEquals(2, reads, "a latched fault prevents a snapshot clock read despite the stale published state")
    }

    @Test fun `clock failures at every sample including AssertionError blank elapsed fields`() {
        for (failureAt in 1..10) {
            var reads = 0
            val failure: Throwable = if (failureAt % 2 == 0) IllegalStateException("diagnostic only") else AssertionError("diagnostic only")
            val phases = WebLogDownloadPhases {
                reads++
                if (reads == failureAt) throw failure
                reads.toLong() * 1_000_000L
            }
            val owner = phases.enter()!!
            owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
            owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.CAPTURE_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.BYTES_READY)
            owner.mark(WebLogDownloadPhases.Phase.HEADERS_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.BODY_CLOSED)
            owner.mark(WebLogDownloadPhases.Phase.EXCHANGE_CLOSED)
            owner.exit(true)
            val suffix = phases.summarySuffix()
            assertTrue(suffix.contains("lp_invalid=1"), "sample $failureAt: $suffix")
            assertTrue(suffix.contains("lp_present=0 lp_saturated=0"), "sample $failureAt: $suffix")
            assertEquals(suffix, phases.summarySuffix())
            assertEquals(failureAt, reads)
        }
    }

    @Test fun `equal instants and submillisecond intervals floor without invalidation`() {
        val values = listOf(7L, 7L, 7L, 7L).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.exit(false)
        val suffix = phases.summarySuffix()
        assertTrue(suffix.contains("lp_invalid=0"), suffix)
        assertTrue(suffix.contains("lp_validated_ms=0"), suffix)
        assertTrue(suffix.contains("lp_exit_ms=0 lp_snapshot_ms=0"), suffix)
    }

    @Test fun `regression at every owner and snapshot sample is sticky`() {
        for (regressAt in 2..10) {
            var reads = 0
            val phases = WebLogDownloadPhases {
                reads++
                if (reads == regressAt) (reads - 2L) * 1_000_000L else reads * 1_000_000L
            }
            val owner = phases.enter()!!
            owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
            owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.CAPTURE_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.BYTES_READY)
            owner.mark(WebLogDownloadPhases.Phase.HEADERS_RETURNED)
            owner.mark(WebLogDownloadPhases.Phase.BODY_CLOSED)
            owner.mark(WebLogDownloadPhases.Phase.EXCHANGE_CLOSED)
            owner.exit(false)
            val suffix = phases.summarySuffix()
            assertTrue(suffix.contains("lp_present=0 lp_saturated=0 lp_invalid=1"), "sample $regressAt: $suffix")
            assertEquals(regressAt, reads)
        }
    }

    @Test fun `long subtraction overflow invalidates all elapsed fields`() {
        val values = listOf(Long.MIN_VALUE, Long.MAX_VALUE).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.exit(false)
        val suffix = phases.summarySuffix()
        assertTrue(suffix.contains("lp_invalid=1 lp_incomplete=0 lp_terminal=2"), suffix)
        assertTrue(suffix.contains("lp_present=0 lp_saturated=0"), suffix)
    }

    @Test fun `floor at cap and saturation above cap are explicit`() {
        val values = listOf(0L, 999_999L, 60_000_999_999L, 60_001_000_000L, 60_001_000_000L, 60_001_000_000L).iterator()
        val phases = WebLogDownloadPhases { values.next() }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.mark(WebLogDownloadPhases.Phase.READ_RETURNED)
        owner.mark(WebLogDownloadPhases.Phase.CAPTURE_RETURNED)
        owner.exit(false)
        val suffix = phases.summarySuffix()
        assertTrue(suffix.contains("lp_saturated=776"), suffix) // capture, branch exit and snapshot
        assertTrue(suffix.contains("lp_validated_ms=0 lp_read_ms=60000 lp_capture_ms=60000"), suffix)
    }

    @Test fun `claimed before publication freezes unavailable without waiting or false zero`() {
        val inClock = CountDownLatch(1)
        val release = CountDownLatch(1)
        val phases = WebLogDownloadPhases {
            inClock.countDown()
            check(release.await(10, TimeUnit.SECONDS))
            0L
        }
        val entrant = Thread { phases.enter() }
        entrant.start()
        try {
            assertTrue(inClock.await(5, TimeUnit.SECONDS))
            assertEquals("", phases.summarySuffix())
            assertEquals(base, base + phases.summarySuffix())
        } finally {
            release.countDown()
            entrant.join(5000)
        }
        assertFalse(entrant.isAlive)
        assertEquals("", phases.summarySuffix())
    }

    @Test fun `losing freezer returns immediately while winner clock is parked`() {
        val reads = AtomicInteger()
        val parked = CountDownLatch(1)
        val release = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val loserValue = java.util.concurrent.atomic.AtomicReference<String?>()
        val loserFailure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val phases = WebLogDownloadPhases {
            if (reads.incrementAndGet() == 4) {
                parked.countDown()
                check(release.await(10, TimeUnit.SECONDS))
            }
            reads.get().toLong() * 1_000_000L
        }
        val owner = phases.enter()!!
        owner.mark(WebLogDownloadPhases.Phase.VALIDATED)
        owner.exit(false)
        val winner = Thread { phases.summarySuffix() }
        val loser = Thread {
            try { loserValue.set(phases.summarySuffix()) }
            catch (failure: Throwable) { loserFailure.set(failure) }
            finally { returned.countDown() }
        }
        winner.start()
        try {
            assertTrue(parked.await(5, TimeUnit.SECONDS))
            loser.start()
            assertTrue(returned.await(2, TimeUnit.SECONDS), "loser must return while the winner clock remains parked")
            assertEquals(null, loserFailure.get())
            assertEquals("", loserValue.get())
            assertEquals(4, reads.get(), "the competing freezer takes no clock sample")
        } finally {
            release.countDown()
            winner.join(5000)
            if (loser.state != Thread.State.NEW) loser.join(5000)
        }
        assertFalse(winner.isAlive)
        assertFalse(loser.isAlive)
        assertEquals(4, reads.get())
    }

    @Test fun `all capped slots fit the worst-case capacity line and unchanged sink grammar`() {
        val values = listOf(0L) + List(10) { 60_001_000_000L }
        val clock = values.iterator()
        val phases = WebLogDownloadPhases { clock.next() }
        val owner = phases.enter()!!
        for (phase in WebLogDownloadPhases.Phase.values()) owner.mark(phase)
        owner.exit(true)
        val suffix = phases.summarySuffix()
        val max = Long.MAX_VALUE.toString()
        val maximumPrefix = "web-capacity-summary successful=$max client_errors=$max server_errors=$max closed_without_response=$max " +
            "overload_responses=$max overload_closed=$max header_deadline_closures=$max request_deadline_closures=$max header_limit_rejections=$max"
        val line = maximumPrefix + suffix
        assertTrue(suffix.toByteArray(Charsets.US_ASCII).size <= WebLogDownloadPhases.MAX_SUFFIX_BYTES)
        assertTrue(line.toByteArray(Charsets.US_ASCII).size + 1 <= WebLogDownloadPhases.MAX_LINE_BYTES)
        assertTrue(line.matches(Regex("web-(?:capacity-summary|overload)(?: [a-z_]+=[0-9]+)+")))
        assertTrue(suffix.contains("lp_present=1023 lp_saturated=1022"), suffix)
        assertEquals(18, suffix.trim().split(' ').size)
    }

    @Test fun `wire suffix and full line remain within fixed bounds`() {
        val phases = WebLogDownloadPhases { 0L }
        val owner = phases.enter()!!
        for (phase in WebLogDownloadPhases.Phase.values()) owner.mark(phase)
        owner.exit(true)
        val suffix = phases.summarySuffix()
        assertTrue(suffix.toByteArray(Charsets.US_ASCII).size <= WebLogDownloadPhases.MAX_SUFFIX_BYTES)
        assertTrue((base + suffix).toByteArray(Charsets.US_ASCII).size + 1 <= WebLogDownloadPhases.MAX_LINE_BYTES)
        assertTrue((base + suffix).matches(Regex("web-(?:capacity-summary|overload)(?: [a-z_]+=[0-9]+)+")))
        assertTrue(suffix.startsWith(" lp_v=1 lp_entries=1 lp_present=1023"))
    }
}
