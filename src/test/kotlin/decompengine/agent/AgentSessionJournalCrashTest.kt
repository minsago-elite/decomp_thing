package decompengine.agent

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class AgentSessionJournalCrashTest {
    @Test fun `abrupt death before prompt blocks unproved cleanup`() = verify("before-prompt")
    @Test fun `abrupt death while streaming retains its durable cursor`() = verify("streaming")
    @Test fun `abrupt death after edit retains unaccepted source bytes`() = verify("after-edit")

    private fun verify(point: String) {
        val directory = createTempDirectory("session-crash-")
        val root = AgentWorkspaceRoot("project", Files.createDirectory(directory.resolve("project")))
        val source = root.path.resolve("artifact.txt")
        Files.writeString(source, "initial")
        val continuation = crashContinuation(directory)
        val log = directory.resolve("child.log")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            AgentSessionJournalCrashFixture::class.java.name, directory.toString(), point,
        ).redirectErrorStream(true).redirectOutput(log.toFile()).apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "child JVM did not terminate")
            assertEquals(86, process.exitValue(), Files.readString(log))
            assertEquals(point, Files.readString(directory.resolve("crash-point")))
            assertFalse(Files.exists(directory.resolve("finally-ran")))
            val sourceBytes = Files.readAllBytes(source)
            assertEquals(if (point == "after-edit") "unaccepted edit" else "initial", String(sourceBytes))
            // Reacquiring ownership must not be mistaken for proof that a peer was cleaned up.
            repeat(2) {
                AgentSessionJournal.open(continuation).use { journal ->
                    assertFailsWith<IllegalStateException> { journal.reconcileWorkspace(listOf(root)) }
                    assertEquals(0, journal.completedTurns)
                    assertNull(journal.acceptedRevisionSha256)
                    if (point != "before-prompt") assertEquals(0L, journal.lastDurableEventSequence)
                }
                assertContentEquals(sourceBytes, Files.readAllBytes(source))
            }
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }
}

private fun crashContinuation(directory: Path) = AgentSessionContinuation(
    directory.resolve("sessions"), "a".repeat(64), "display-task",
    mapOf(AgentWorkspacePath("project", "artifact.txt") to MessageDigest.getInstance("SHA-256")
        .digest("initial".toByteArray()).joinToString("") { "%02x".format(it) }),
)

/** Abrupt journal-owner exit only: no ACP peer, compiler, or target process is launched. */
object AgentSessionJournalCrashFixture {
    @JvmStatic fun main(args: Array<String>) {
        val directory = Path.of(args[0])
        val point = args[1]
        try {
            AgentSessionJournal.open(crashContinuation(directory)).use { journal ->
                journal.reconcileWorkspace(listOf(AgentWorkspaceRoot("project", directory.resolve("project"))))
                journal.processStarting("b".repeat(64))
                journal.chooseSession(mapOf("configuration" to "fixed"), true)
                journal.sessionReady("fixture-session", false)
                if (point != "before-prompt") {
                    journal.promptStarting()
                    journal.event(AgentMessageEvent(0, "message", AgentMessageRole.ASSISTANT, "partial"))
                }
                if (point == "after-edit") Files.writeString(directory.resolve("project/artifact.txt"), "unaccepted edit")
                Files.writeString(directory.resolve("crash-point"), point)
                Runtime.getRuntime().halt(86)
            }
        } finally {
            Files.writeString(directory.resolve("finally-ran"), "unexpected orderly cleanup")
        }
    }
}
