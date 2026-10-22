package decompengine.web

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebPassiveHarnessReadinessTest {
    private fun unchecked(configuration: String = "configuration-a", key: String = "helpers-a") =
        WebHarnessReadiness("unknown", "SANDBOX_HELPER_UNCHECKED", "unchecked", configuration, key)

    private fun observed(configuration: String = "configuration-a", key: String = "helpers-a") =
        WebHarnessReadiness("supported", null, "observed", configuration, key)

    @Test
    fun `passive reads never run the explicit inspection callback`() {
        var now = 0L
        var inspections = 0
        val projector = WebHarnessReadinessProjector(
            probe = { unchecked() }, ttlNanos = 100, nanoTime = { now },
            inspectionProbe = { inspections++; observed() },
        )
        try {
            repeat(3) {
                assertEquals("unknown", projector.current().state)
                now += 100
            }
            assertEquals(0, inspections)
            assertEquals("supported", projector.inspect().state)
            assertEquals("supported", projector.current().state)
            assertEquals(1, inspections)
        } finally { projector.close() }
    }

    @Test
    fun `only a matching configuration and helper observation can make readiness available`() {
        var inspection = observed(configuration = "configuration-b")
        val projector = WebHarnessReadinessProjector(
            probe = { unchecked() }, inspectionProbe = { inspection },
        )
        try {
            projector.inspect()
            assertEquals("unknown", projector.current().state)
            inspection = observed(key = "helpers-b")
            projector.inspect()
            assertEquals("unknown", projector.current().state)
            inspection = observed()
            projector.inspect()
            assertEquals("supported", projector.current().state)
        } finally { projector.close() }
    }

    @Test
    fun `helper observations expire without launching another inspection`() {
        var now = 0L
        var inspections = 0
        val projector = WebHarnessReadinessProjector(
            probe = { unchecked() }, ttlNanos = 100, nanoTime = { now },
            inspectionProbe = { inspections++; observed() },
        )
        try {
            projector.inspect()
            now = 99
            assertEquals("supported", projector.current().state)
            now = 100
            assertEquals("unknown", projector.current().state)
            assertEquals(1, inspections)
        } finally { projector.close() }
    }

    @Test
    fun `an old helper observation cannot promote an unavailable configuration`() {
        var now = 0L
        var configuration = unchecked()
        val projector = WebHarnessReadinessProjector(
            probe = { configuration }, ttlNanos = 100, nanoTime = { now },
            inspectionProbe = { observed() },
        )
        try {
            assertEquals("unknown", projector.current().state)
            now = 50
            projector.inspect()
            assertEquals("supported", projector.current().state)
            configuration = WebHarnessReadiness("unavailable", "HARNESS_CONFIGURATION_INVALID", "invalid")
            now = 100
            assertEquals(configuration, projector.current())
        } finally { projector.close() }
    }

    @Test
    fun `an agent inspection for another configuration cannot claim a configured agent started`() {
        val readiness = observed()
        val stale = WebAgentPreflightSnapshot("ready", "inspection-b", null, "configuration-b")
        assertTrue(readiness.withAgentInspection(stale).message.contains("unproven"))
        assertFalse(readiness.withAgentInspection(stale).message.contains("last operator inspection started"))
        val matching = stale.copy(configurationIdentity = "configuration-a")
        assertTrue(readiness.withAgentInspection(matching).message.contains("last operator inspection started"))
        assertEquals("unknown", unchecked().withAgentInspection(matching).state)
        assertEquals("supported", readiness.withAgentInspection(stale.copy(status = "failed")).state)
        assertEquals("unavailable", readiness.withAgentInspection(matching.copy(status = "failed")).state)
        assertEquals("unavailable", unchecked().withAgentInspection(matching.copy(status = "failed")).state)
    }

    @Test
    fun `a slow metadata read cannot extend an explicit observation lifetime`() {
        var now = 0L
        val projector = WebHarnessReadinessProjector(
            probe = { now += 2; unchecked() }, ttlNanos = 100, nanoTime = { now },
            inspectionProbe = { observed() },
        )
        try {
            projector.inspect()
            now = 99
            assertEquals("unknown", projector.current().state)
        } finally { projector.close() }
    }
}
