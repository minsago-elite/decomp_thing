package decompengine.analysis

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame

/** In-memory exit observations and callbacks only; no Process, controller, thread, timer or native trial. */
class AnalysisArtifactStagingAbsenceTest {
    @Test fun `exited handles cannot retire staging while Java exit notification still lags`() {
        val javaObservations = ArrayDeque(listOf(true, true, true, false))
        var waits = 0
        awaitReportStagingProcessAbsence({ javaObservations.removeFirst() }, { false }) { waits++ }
        assertEquals(3, waits)
        assertEquals(0, javaObservations.size)
    }
    @Test fun `exited Java process cannot retire staging while a recorded handle remains alive`() {
        val handleObservations = ArrayDeque(listOf(true, true, false))
        var waits = 0
        awaitReportStagingProcessAbsence({ false }, { handleObservations.removeFirst() }) { waits++ }
        assertEquals(2, waits)
        assertEquals(0, handleObservations.size)
    }
    @Test fun `independent exit transitions must both settle before the wait returns`() {
        var javaAlive = true; var handleAlive = true; var waits = 0
        awaitReportStagingProcessAbsence({ javaAlive }, { handleAlive }) {
            waits++
            if (waits == 1) javaAlive = false else handleAlive = false
        }
        assertEquals(2, waits)
        assertEquals(false, javaAlive); assertEquals(false, handleAlive)
    }
    @Test fun `waiting callback refusal is preserved instead of becoming an absence observation`() {
        val refusal = IllegalStateException("authored waiting refusal")
        var waits = 0
        val observed = assertFailsWith<IllegalStateException> {
            awaitReportStagingProcessAbsence({ true }, { false }) { waits++; throw refusal }
        }
        assertSame(refusal, observed); assertEquals(1, waits)
    }
    @Test fun `already settled exit observations need no additional waiting callback`() {
        var javaReads = 0; var handleReads = 0; var waits = 0
        awaitReportStagingProcessAbsence({ javaReads++; false }, { handleReads++; false }) { waits++ }
        assertEquals(1, javaReads); assertEquals(1, handleReads); assertEquals(0, waits)
    }
}
