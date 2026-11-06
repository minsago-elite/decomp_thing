package decompengine.acp

import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class WorkspaceChangeSetTest {
    @Test
    fun `unique nonempty content pair is deterministic while paths remain explicit`() {
        val source = path("src/old.c")
        val destination = path("src/new.c")
        val other = path("src/other.c")
        val sourceDeletion = deletion(source, sha = "a".repeat(64), size = 7)
        val destinationCreation = creation(destination, sha = "a".repeat(64), size = 7)
        val unrelated = creation(other, sha = "b".repeat(64), size = 3)

        val first = WorkspaceChangeSetClassifier.classify(listOf(unrelated, destinationCreation, sourceDeletion))
        val second = WorkspaceChangeSetClassifier.classify(listOf(sourceDeletion, unrelated, destinationCreation))

        assertEquals(first, second)
        assertEquals(listOf(destination, source, other), first.changes.map { it.path })
        assertEquals(1, first.moveCandidates.size)
        val move = first.moveCandidates.single()
        assertEquals(source, move.sourcePath)
        assertEquals(destination, move.destinationPath)
        assertEquals("a".repeat(64), move.contentSha256)
        assertEquals(7, move.sizeBytes)
        assertEquals(listOf(AgentFileChangeKind.CREATED, AgentFileChangeKind.DELETED, AgentFileChangeKind.CREATED),
            first.changes.map { it.kind })
        val execution = AgentExecutionResult(
            stopReason = AgentStopReason.COMPLETED,
            changes = first.changes,
            moveCandidates = first.moveCandidates,
        )
        assertEquals(first.moveCandidates, execution.moveCandidates)
        assertEquals(first.changes, execution.changes)
    }

    @Test
    fun `ambiguous content matches remain only explicit additions and deletions`() {
        val deletionA = deletion(path("src/a"), "a".repeat(64), 12)
        val deletionB = deletion(path("src/b"), "a".repeat(64), 12)
        val creation = creation(path("src/c"), "a".repeat(64), 12)
        val changeSet = WorkspaceChangeSetClassifier.classify(listOf(creation, deletionB, deletionA))

        assertTrue(changeSet.moveCandidates.isEmpty())
        assertEquals(listOf("src/a", "src/b", "src/c"), changeSet.changes.map { it.path.relativePath })
        assertEquals(
            listOf(AgentFileChangeKind.DELETED, AgentFileChangeKind.DELETED, AgentFileChangeKind.CREATED),
            changeSet.changes.map { it.kind },
        )
    }

    @Test
    fun `empty content is never used to infer a move`() {
        val changeSet = WorkspaceChangeSetClassifier.classify(
            listOf(deletion(path("src/empty-old"), "e".repeat(64), 0), creation(path("src/empty-new"), "e".repeat(64), 0)),
        )

        assertTrue(changeSet.moveCandidates.isEmpty())
        assertEquals(2, changeSet.changes.size)
    }

    @Test
    fun `duplicate paths are rejected before a change set is returned`() {
        val change = creation(path("src/same"), "c".repeat(64), 1)
        assertFailsWith<IllegalArgumentException> {
            WorkspaceChangeSetClassifier.classify(listOf(change, change))
        }
    }

    @Test
    fun `large classifications periodically observe cancellation and deadline checkpoints`() {
        val changes = (0 until 130).flatMap { index ->
            val sha = index.toString(16).padStart(64, '0')
            listOf(
                deletion(path("src/old-$index"), sha, index + 1L),
                creation(path("src/new-$index"), sha, index + 1L),
            )
        }
        var checkpoints = 0

        val changeSet = WorkspaceChangeSetClassifier.classify(changes) { checkpoints++ }

        assertEquals(260, changeSet.changes.size)
        assertEquals(130, changeSet.moveCandidates.size)
        assertTrue(checkpoints >= 9, "expected checkpoints across indexing, pairing and result construction")
    }

    private fun path(relative: String) = AgentWorkspacePath("project", relative)

    private fun deletion(path: AgentWorkspacePath, sha: String, size: Long) =
        WorkspaceSnapshotChange(path, AgentFileChangeKind.DELETED, sha, null, size, null)

    private fun creation(path: AgentWorkspacePath, sha: String, size: Long) =
        WorkspaceSnapshotChange(path, AgentFileChangeKind.CREATED, null, sha, null, size)
}
