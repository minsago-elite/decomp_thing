package decompengine.oracle.fulltree

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class ContainedCommandOperationDeadlineTest {
    @Test
    fun `both legs and the retained-owner gap consume the same deadline`() {
        var now = 5_000_000_000L
        val deadline = ContainedCommandOperationDeadline(10_000) { now }
        val policy = deadline.policy
        assertEquals(10_000, deadline.remainingWholeSecondsMillis(10_000))
        now += 3_250_000_000L
        assertEquals(6_000, deadline.remainingWholeSecondsMillis(10_000))
        now += 2_000_000_000L
        assertEquals(4_750, deadline.remainingMillis(10_000))
        assertEquals(4_000, deadline.remainingWholeSecondsMillis(10_000))
        assertEquals(policy, deadline.policy)
        val receipt = deadline.snapshot()
        assertEquals(5_250_000_000L, receipt.getValue("elapsedNanos").jsonPrimitive.long)
        assertEquals(4_750_000_000L, receipt.getValue("remainingNanos").jsonPrimitive.long)
        now += 4_750_000_000L
        assertFails { deadline.requireCurrent() }
        now = 5_000_000_000L
        assertFails { deadline.remainingMillis(10_000) }
    }

    @Test
    fun `service budgets round down and never grow caller ceilings`() {
        var now = 0L
        val deadline = ContainedCommandOperationDeadline(2_000) { now }
        assertEquals(1_000, deadline.remainingWholeSecondsMillis(1_500))
        now = 1_000_000_001L
        assertEquals(999, deadline.remainingMillis(2_000))
        assertFails { deadline.remainingWholeSecondsMillis(2_000) }
        now = 1_999_000_001L
        assertFails { deadline.remainingMillis(2_000) }
        assertFails { deadline.remainingMillis(0) }
    }

    @Test
    fun `monotonic wrap is supported but a regressed clock revokes the deadline`() {
        var now = Long.MAX_VALUE - 3_000_000L
        val wrapped = ContainedCommandOperationDeadline(2_000) { now }
        now += 10_000_000L
        assertEquals(1_990, wrapped.remainingMillis(2_000))
        var clock = 10L
        val regressed = ContainedCommandOperationDeadline(1_000) { clock }
        clock = 9L
        assertFails { regressed.requireCurrent() }
        clock = 11L
        assertFails { regressed.snapshot() }
    }

    @Test
    fun `operation deadlines require finite whole-second policy bounds`() {
        for (budget in listOf(0L, 999L, 1_001L, 86_400_001L, Long.MAX_VALUE)) {
            assertFails { ContainedCommandOperationDeadline(budget) }
        }
    }
}
