package decompengine.jobs

import decompengine.agent.AgentWorkflowPhase
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BestEffortProgressJournalTest {
    @Test
    fun `busy journal preserves workflow failure and existing owner`() {
        val reports = createTempDirectory("progress-busy-")
        AgentProgressJournal(reports, "reconstruction").use { owner ->
            val failure = assertFailsWith<IllegalStateException> {
                BestEffortProgressJournal(reports, "reconstruction").use { progress ->
                    progress.phase(AgentWorkflowPhase.ANALYZING)
                    error("workflow failure")
                }
            }
            assertEquals("workflow failure", failure.message)
            owner.phase(AgentWorkflowPhase.COMPLETED)
        }
        assertTrue(AgentProgressJournal.read(reports) != null)
    }

    @Test
    fun `failed observer disables further callbacks and releases writer`() {
        val reports = createTempDirectory("progress-observer-")
        var calls = 0
        BestEffortProgressJournal(reports, "reconstruction", onPhase = {
            calls++
            error("private observer failure")
        }).use { progress ->
            progress.phase(AgentWorkflowPhase.ANALYZING)
            progress.phase(AgentWorkflowPhase.COMPLETED)
        }
        assertEquals(1, calls)
        AgentProgressJournal(reports, "reconstruction").use { it.phase(AgentWorkflowPhase.COMPLETED) }
    }

    @Test
    fun `interrupted close preserves interruption and releases writer`() {
        val reports = createTempDirectory("progress-interrupted-")
        val progress = BestEffortProgressJournal(reports, "reconstruction")
        progress.phase(AgentWorkflowPhase.ANALYZING)
        Thread.currentThread().interrupt()
        try {
            progress.close()
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
        AgentProgressJournal(reports, "reconstruction").close()
    }
}
