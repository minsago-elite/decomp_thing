package decompengine.jobs

import decompengine.agent.AgentWorkflowPhase
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BestEffortProgressJournalTest {
    @Test
    fun `throwing unavailable warnings preserve original failure interruption and journal owner`(): Unit {
        val parent = java.nio.file.Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-warning").toAbsolutePath())
        for (warningFailure in listOf(IllegalStateException("PRIVATE-warning"), InterruptedException("PRIVATE-warning"))) {
            val reports = createTempDirectory(parent, "journal-")
            val workflowFailure = IllegalStateException("original workflow failure")
            var warnings = 0
            AgentProgressJournal(reports, "reconstruction").use { owner ->
                try {
                    val observed = assertFailsWith<IllegalStateException> {
                        BestEffortProgressJournal(reports, "reconstruction", onUnavailable = {
                            warnings++
                            throw warningFailure
                        }).use { progress ->
                            progress.phase(AgentWorkflowPhase.ANALYZING)
                            assertEquals(warningFailure is InterruptedException, Thread.currentThread().isInterrupted)
                            throw workflowFailure
                        }
                    }
                    kotlin.test.assertSame(workflowFailure, observed)
                    assertEquals(1, warnings)
                    assertEquals(warningFailure is InterruptedException, Thread.currentThread().isInterrupted)
                } finally { Thread.interrupted() }
                // The failed display wrapper cannot release or mutate this other writer's lease.
                owner.phase(AgentWorkflowPhase.COMPLETED)
            }
            val snapshot = kotlin.test.assertNotNull(AgentProgressJournal.read(reports))
            kotlin.test.assertFalse(snapshot.toString().contains("PRIVATE-warning"))
            AgentProgressJournal(reports, "reconstruction").use { it.phase(AgentWorkflowPhase.COMPLETED) }
        }
    }

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
