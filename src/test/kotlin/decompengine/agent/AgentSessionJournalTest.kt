package decompengine.agent

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.*
import org.junit.jupiter.api.io.TempDir

class AgentSessionJournalTest {
    @TempDir lateinit var directory: Path

    @Test
    fun `completed conversation loads after reopening and accepted publication is idempotent`() {
        val fixture = fixture()
        val request = fixture.request(fixture.continuation())
        AgentSessionJournal.open(request.sessionContinuation!!).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            journal.processStarting(AgentExecutionRequestBinding.capture(request).requestSha256)
            assertNull(journal.chooseSession(identity, true))
            journal.sessionReady("remote-session", false)
            journal.promptStarting()
            journal.event(AgentMessageEvent(0, "message", AgentMessageRole.ASSISTANT, "done", true))
            journal.finishTurn(receipt(request), true)
        }
        Files.writeString(fixture.source, "accepted candidate")
        val revision = sha(Files.readAllBytes(fixture.source))
        val accepted = fixture.continuation(accepted = revision)
        val requestSha = AgentExecutionRequestBinding.capture(request).requestSha256
        AgentSessionJournal.recordAcceptance(accepted, listOf(fixture.root), requestSha, "c".repeat(64), revision)
        val before = Files.readAllBytes(accepted.directory.resolve("session.json"))
        AgentSessionJournal.recordAcceptance(accepted, listOf(fixture.root), requestSha, "c".repeat(64), revision)
        assertContentEquals(before, Files.readAllBytes(accepted.directory.resolve("session.json")))
        AgentSessionJournal.open(accepted).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            assertEquals(1, journal.completedTurns)
            assertEquals(0L, journal.lastDurableEventSequence)
            assertEquals(revision, journal.acceptedRevisionSha256)
            assertEquals("remote-session", journal.chooseSession(identity, true))
        }
    }

    @Test
    fun `unsupported load records new conversation while retaining accepted project evidence`() {
        val fixture = fixture()
        complete(fixture, advertised = false)
        AgentSessionJournal.open(fixture.continuation()).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            assertNull(journal.chooseSession(identity, false))
            assertEquals("new-load-unsupported-project-evidence", journal.decision)
            assertEquals(1, journal.completedTurns)
        }
    }

    @Test
    fun `load failure requires recorded explicit new session policy`() {
        val fixture = fixture()
        complete(fixture)
        AgentSessionJournal.open(fixture.continuation()).use { journal ->
            assertEquals("remote-session", journal.chooseSession(identity, true))
            journal.loadFailed()
        }
        AgentSessionJournal.open(fixture.continuation()).use { journal ->
            assertFailsWith<IllegalStateException> { journal.chooseSession(identity, true) }
        }
        AgentSessionJournal.open(fixture.continuation(policy = AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE)).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            assertNull(journal.chooseSession(identity, true))
            assertEquals("new-explicit-project-evidence", journal.decision)
        }
    }

    @Test
    fun `unknown edits after a turn quarantine the operation without altering source bytes`() {
        val fixture = fixture()
        complete(fixture)
        val before = fixture.continuation()
        Files.writeString(fixture.source, "unvalidated candidate")
        AgentSessionJournal.open(before).use { journal ->
            assertFailsWith<IllegalStateException> { journal.reconcileWorkspace(listOf(fixture.root)) }
        }
        assertEquals("unvalidated candidate", Files.readString(fixture.source))
        assertTrue(Files.readString(before.directory.resolve("quarantine.json")).contains("unexplained-workspace-edits"))
        AgentSessionJournal.open(before).use { journal ->
            assertFailsWith<IllegalStateException> { journal.reconcileWorkspace(listOf(fixture.root)) }
        }
    }

    @Test
    fun `different configured agent and capabilities cannot reuse a recorded session`() {
        val fixture = fixture()
        complete(fixture)
        AgentSessionJournal.open(fixture.continuation()).use { journal ->
            assertFailsWith<IllegalStateException> { journal.chooseSession(identity + ("configuration" to "changed"), true) }
            assertEquals("agent-configuration-protocol-capability-identity-mismatch", journal.decision)
        }
    }

    @Test
    fun `interrupted process without cleanup proof cannot restart or infer acceptance`() {
        val fixture = fixture()
        val continuation = fixture.continuation()
        val request = fixture.request(continuation)
        AgentSessionJournal.open(continuation).use { journal ->
            journal.processStarting(AgentExecutionRequestBinding.capture(request).requestSha256)
            journal.chooseSession(identity, true)
            journal.sessionReady("remote-session", false)
            journal.promptStarting()
            journal.event(AgentMessageEvent(0, "stream", AgentMessageRole.ASSISTANT, "partial"))
        }
        AgentSessionJournal.open(continuation).use { journal ->
            assertFailsWith<IllegalStateException> { journal.reconcileWorkspace(listOf(fixture.root)) }
            assertEquals(0, journal.completedTurns)
            assertNull(journal.acceptedRevisionSha256)
        }
    }

    @Test
    fun `clean cancellation preserves evidence and explicitly recreates the conversation`() {
        val fixture = fixture()
        val continuation = fixture.continuation()
        val request = fixture.request(continuation)
        AgentSessionJournal.open(continuation).use { journal ->
            journal.processStarting(AgentExecutionRequestBinding.capture(request).requestSha256)
            journal.chooseSession(identity, true)
            journal.sessionReady("remote-session", false)
            journal.finishTurn(receipt(request, AgentStopReason.CANCELLED), true)
        }
        AgentSessionJournal.open(continuation).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            assertNull(journal.chooseSession(identity, true))
            assertEquals("new-interrupted-turn-project-evidence", journal.decision)
            assertEquals(0, journal.completedTurns)
        }
    }

    @Test
    fun `request receipt commits continuation policy and a second journal owner is rejected`() {
        val fixture = fixture()
        val continuation = fixture.continuation()
        val first = fixture.request(continuation)
        val second = fixture.request(fixture.continuation(policy = AgentSessionResumePolicy.NEW_SESSION_FROM_PROJECT_EVIDENCE))
        assertNotEquals(AgentExecutionRequestBinding.capture(first), AgentExecutionRequestBinding.capture(second))
        AgentSessionJournal.open(continuation).use {
            assertFails { AgentSessionJournal.open(continuation) }
        }
        AgentSessionJournal.open(continuation).close()
    }

    @Test
    fun `admission cancellation is checked while hashing and publishes no turn`() {
        val fixture = fixture()
        var checks = 0
        AgentSessionJournal.open(fixture.continuation()).use { journal ->
            assertFailsWith<InterruptedException> {
                journal.reconcileWorkspace(listOf(fixture.root)) {
                    if (++checks == 2) throw InterruptedException("cancelled")
                }
            }
            assertEquals(0, journal.completedTurns)
            assertNull(journal.sessionId)
        }
        AgentSessionJournal.open(fixture.continuation()).use { journal -> journal.reconcileWorkspace(listOf(fixture.root)) }
    }

    @Test
    fun `workspace inventory enforces one aggregate hash budget`() {
        val fixture = fixture()
        val paths = (1..3).map { number ->
            val path = fixture.root.path.resolve("source$number.c")
            java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.CREATE_NEW, java.nio.file.StandardOpenOption.WRITE).use {
                it.position(16L * 1024 * 1024 - 1)
                it.write(java.nio.ByteBuffer.wrap(byteArrayOf(0)))
            }
            AgentWorkspacePath(fixture.root.id, path.fileName.toString())
        }
        val failure = assertFailsWith<IllegalArgumentException> {
            AgentSessionJournal.captureWorkspaceFiles(paths, listOf(fixture.root))
        }
        assertTrue(failure.message.orEmpty().contains("aggregate"))
    }

    @Test
    fun `journal owner rejects unexplained durable metadata replacement`() {
        val fixture = fixture()
        val continuation = fixture.continuation()
        AgentSessionJournal.open(continuation).use { journal ->
            Files.writeString(continuation.directory.resolve("session.json"), "{}")
            assertFailsWith<IllegalStateException> { journal.chooseSession(identity, true) }
        }
    }

    @Test
    fun `oversized initial inventory cannot publish a journal that cannot be reopened`() {
        val files = (1..4096).associate { index ->
            AgentWorkspacePath("project", "module$index/" + "a".repeat(256)) to "b".repeat(64)
        }
        val continuation = AgentSessionContinuation(directory.resolve("sessions"), "a".repeat(64), "module", files)
        val failure = assertFailsWith<IllegalArgumentException> { AgentSessionJournal.open(continuation) }
        assertTrue(failure.message.orEmpty().contains("byte bound"))
        assertFalse(Files.exists(continuation.directory.resolve("session.json")))
    }

    private fun complete(fixture: Fixture, advertised: Boolean = true) {
        val continuation = fixture.continuation()
        val request = fixture.request(continuation)
        AgentSessionJournal.open(continuation).use { journal ->
            journal.reconcileWorkspace(listOf(fixture.root))
            journal.processStarting(AgentExecutionRequestBinding.capture(request).requestSha256)
            journal.chooseSession(identity, advertised)
            journal.sessionReady("remote-session", false)
            journal.promptStarting()
            journal.finishTurn(receipt(request), true)
        }
    }

    private fun fixture(): Fixture {
        val root = AgentWorkspaceRoot("project", Files.createDirectory(directory.resolve("project")))
        val source = root.path.resolve("module.c")
        Files.writeString(source, "initial")
        return Fixture(root, source, directory.resolve("sessions"))
    }

    private data class Fixture(val root: AgentWorkspaceRoot, val source: Path, val sessionDirectory: Path) {
        fun continuation(accepted: String? = null, policy: AgentSessionResumePolicy = AgentSessionResumePolicy.LOAD_OR_NEW_WHEN_UNSUPPORTED) =
            AgentSessionContinuation(
                sessionDirectory, "a".repeat(64), "module",
                mapOf(AgentWorkspacePath(root.id, "module.c") to sha(Files.readAllBytes(source))),
                accepted, policy,
            )
        fun request(continuation: AgentSessionContinuation) = AgentExecutionRequest(
            "reconstruct module", listOf(root),
            accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(
                AgentWorkspacePath(root.id, "module.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE),
            ))),
            sessionContinuation = continuation,
        )
    }

    private fun receipt(request: AgentExecutionRequest, reason: AgentStopReason = AgentStopReason.COMPLETED) =
        AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(AgentExecutionResult(reason)))

    companion object {
        private val identity = mapOf("configuration" to "fixed", "implementation" to "agent-1", "capabilities" to "stable")
        private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}

