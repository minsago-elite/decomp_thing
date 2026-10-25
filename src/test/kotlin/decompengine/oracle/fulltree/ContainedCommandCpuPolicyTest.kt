package decompengine.oracle.fulltree

import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Test

class ContainedCommandCpuPolicyTest {
    @Test
    fun `processor admission has an independent ceiling and preserves aggregate compute`() {
        val serial = KotlinSystemdCgroupCommandResources(9_000_000L, 16L * 1024 * 1024 * 1024, 128, 1024)
        val parallel = serial.copy(processorCount = 4)
        assertEquals(serial.aggregateCpuSeconds, parallel.aggregateCpuSeconds)
        assertEquals(setOf("wallClockMillis", "maximumResidentBytes", "pidsMax", "maximumFileBytes"), serial.json().keys)
        assertEquals(serial.json().keys + "processorCount", parallel.json().keys)
        assertFailsWith<IllegalArgumentException> { serial.copy(processorCount = 0) }
        assertFailsWith<IllegalArgumentException> { serial.copy(processorCount = 5) }
        assertFailsWith<IllegalArgumentException> { ContainedCommandCpuCapacity(64, null, "/").requireCapacity(5) }
        ContainedCommandCpuCapacity(4, 4, "/user.slice").requireCapacity(4)
        assertFailsWith<IllegalArgumentException> { ContainedCommandCpuCapacity(3, null, "/").requireCapacity(4) }
        assertFailsWith<IllegalArgumentException> { ContainedCommandCpuCapacity(64, 3, "/").requireCapacity(4) }
    }

    @Test
    fun `kernel affinity ranges are counted without overlaps or unbounded allocation`() {
        assertEquals(4, parseContainedCommandCpuAffinity("0-3"))
        assertEquals(4, parseContainedCommandCpuAffinity("2,4-5,9"))
        assertEquals(65_536, parseContainedCommandCpuAffinity("0-65535"))
        for (bad in listOf("", "0-3,3", "4,2", "1-0", "0-65536", "0,01", "0--1", "1-2-3", "0,", "-1")) {
            assertFailsWith<IllegalArgumentException>(bad) { parseContainedCommandCpuAffinity(bad) }
        }
    }

    @Test
    fun `the strictest ancestor CPU quota limits admission including fractional quotas`() {
        assertNull(minimumContainedCommandCpuQuota(listOf("max 100000", "max 1000")))
        assertEquals(4, minimumContainedCommandCpuQuota(listOf("max 100000", "800000 100000", "4000 1000")))
        assertEquals(3, minimumContainedCommandCpuQuota(listOf("400000 100000", "350000 100000")))
        assertEquals(0, minimumContainedCommandCpuQuota(listOf("99999 100000")))
        for (bad in listOf("max", "max 0", "0 100000", "-4 100000", "400000 100000 extra", "400000 1000001")) {
            assertFailsWith<IllegalArgumentException>(bad) { minimumContainedCommandCpuQuota(listOf(bad)) }
        }
        assertFailsWith<IllegalArgumentException> { minimumContainedCommandCpuQuota(emptyList()) }
        assertFailsWith<IllegalArgumentException> { minimumContainedCommandCpuQuota(List(130) { "max 100000" }) }
    }

    @Test
    fun `live cgroup CPU quota must match the selected concurrency exactly`() {
        assertTrue(containedCommandCpuQuotaMatches("100000 100000", 1))
        assertTrue(containedCommandCpuQuotaMatches("400000 100000\n", 4))
        assertTrue(containedCommandCpuQuotaMatches("4000 1000", 4))
        for (bad in listOf("max 100000", "100000 100000", "399999 100000", "400001 100000", "0 0", "-4 1", "4 0", "4 1 extra", "9223372036854775807 100000")) {
            assertFalse(containedCommandCpuQuotaMatches(bad, 4), bad)
        }
        assertFalse(containedCommandCpuQuotaMatches("500000 100000", 5))
    }

    @Test
    fun `live CPU monitor stops before the unchanged aggregate bound to reserve cleanup`() {
        assertEquals(8_968_000_000L, containedCommandCpuStopThresholdUsec(9_000L, 4, 8_000L))
        assertEquals(8_992_000_000L, containedCommandCpuStopThresholdUsec(9_000L, 1, 8_000L))
        assertFailsWith<IllegalArgumentException> { containedCommandCpuStopThresholdUsec(32L, 4, 8_000L) }
        assertFailsWith<IllegalArgumentException> { containedCommandCpuStopThresholdUsec(9_000L, 5, 8_000L) }
        assertFailsWith<ArithmeticException> { containedCommandCpuStopThresholdUsec(Long.MAX_VALUE, 4, 8_000L) }
    }

    @Test
    fun `aggregate CPU exhaustion kills the pinned tree before failing control cleanup`() {
        val monitor = ContainedCommandCpuBudgetMonitor(100L, 4, 8_000L)
        val events = arrayListOf<String>()
        monitor.observe(60_000_000L, { events += "kill" }, { events += "control" })
        assertTrue(events.isEmpty())
        // Four workers have used 17 CPU seconds apiece: each is below its own process limit.
        val failure = assertFailsWith<IllegalArgumentException> {
            monitor.observe(4L * 17_000_000L, { events += "kill" }, {
                assertEquals(listOf("kill"), events)
                events += "control"
                error("systemd control did not complete")
            })
        }
        assertEquals(listOf("kill", "control"), events)
        assertEquals(
            "contained command exhausted its aggregate CPU allowance and cleanup reserve: " +
                "usageUsec=68000000 stopThresholdUsec=68000000",
            failure.message,
        )
        assertEquals("systemd control did not complete", failure.suppressed.single().message)
        assertFailsWith<IllegalStateException> {
            monitor.observe(68_000_001L, { error("must not resume") }, { error("must not resume") })
        }
        val overshoot = assertFailsWith<IllegalArgumentException> {
            ContainedCommandCpuBudgetMonitor(100L, 4, 8_000L).observe(68_123_456L, {}, {})
        }
        assertEquals(
            "contained command exhausted its aggregate CPU allowance and cleanup reserve: " +
                "usageUsec=68123456 stopThresholdUsec=68000000",
            overshoot.message,
        )
    }
}
