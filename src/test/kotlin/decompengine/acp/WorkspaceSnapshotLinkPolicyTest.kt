package decompengine.acp

import decompengine.agent.AgentCancellation
import java.io.IOException
import java.time.Duration
import kotlin.test.*

/** Metadata/callback composition only; no filesystem, agent, process or native context. */
class WorkspaceSnapshotLinkPolicyTest {
    @Test fun `unsupported links are refused before capture charges file and byte budgets`() {
        val budget = WorkspaceSnapshotBudget(AgentCancellation.NONE, MonotonicDeadline(Duration.ofMinutes(1)),
            honorCancellation = false, limits = WorkspaceSnapshotLimits(entries = 1, files = 1, fileBytes = 1, totalBytes = 1))
        var captures = 0
        for (links in listOf(-1, 0, 2, 3, Int.MAX_VALUE)) {
            val failure = assertFailsWith<WorkspaceSnapshotInvalidEntry> {
                withSingleLinkWorkspaceSnapshotFile(links) {
                    captures++
                    budget.file()
                    budget.declaredSize(1)
                    budget.readBytes(1, 1)
                    error("Unsupported metadata must not reach capture work")
                }
            }
            assertEquals("unsupported-link-count", failure.reason)
        }
        assertEquals(0, captures)

        val expected = Any()
        val captured = withSingleLinkWorkspaceSnapshotFile(1) {
            captures++
            budget.file()
            budget.declaredSize(1)
            budget.readBytes(1, 1)
            expected
        }
        assertSame(expected, captured)
        assertEquals(1, captures)
        assertEquals("file-count", assertFailsWith<WorkspaceSnapshotLimitExceeded> { budget.file() }.dimension)
        assertEquals("total-bytes", assertFailsWith<WorkspaceSnapshotLimitExceeded> { budget.declaredSize(1) }.dimension)
    }

    @Test fun `single-link capture preserves the original failure without retry or reclassification`() {
        val original = IOException("synthetic capture failure")
        var captures = 0
        val failure = assertFailsWith<IOException> {
            withSingleLinkWorkspaceSnapshotFile(1) {
                captures++
                throw original
            }
        }
        assertSame(original, failure)
        assertEquals(1, captures)
    }
}
