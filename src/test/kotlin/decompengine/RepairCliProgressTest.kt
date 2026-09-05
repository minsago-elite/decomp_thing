package decompengine

import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

class RepairCliProgressTest {
    @Test
    fun `cursor skips prior history reports gaps and never copies peer text`() {
        val cursor = RepairCliProgressCursor(snapshot(5, emptyList()))
        val lines = cursor.advance(snapshot(8, listOf(event(4, "accepted"), event(5, "provisional"), event(7, "exhausted"))))
        assertEquals(3, lines.size)
        assertTrue(lines.first().contains("omitted 1 event"))
        assertTrue(lines[1].endsWith(": provisional"))
        assertTrue(lines[2].endsWith(": exhausted"))
        assertFalse(lines.joinToString().contains("private"))
        assertTrue(cursor.advance(snapshot(8, emptyList())).isEmpty())
    }

    @Test
    fun `one poll bounds phase output and marks omitted older updates`() {
        val cursor = RepairCliProgressCursor(null)
        val lines = cursor.advance(snapshot(50, (0L..49).map { event(it, "build_validating") }))
        assertEquals(33, lines.size)
        assertTrue(lines.first().contains("18 older phase"))
        assertTrue(cursor.advance(snapshot(1, listOf(event(0, "unresolved")))).first().contains("history restarted"))
    }

    @Test
    fun `live observer delivers persisted repair states with digest correlation`() {
        val root = createTempDirectory("repair-cli-progress-")
        val observed = CountDownLatch(1)
        val bytes = object : ByteArrayOutputStream() {
            @Synchronized override fun write(value: ByteArray, offset: Int, length: Int) {
                super.write(value, offset, length)
                if (toString(Charsets.UTF_8).contains(": exhausted")) observed.countDown()
            }
        }
        PrintStream(bytes, true, Charsets.UTF_8).use { output ->
            RepairCliProgress(root, output).use {
                AgentProgressJournal(root, "repair").use { journal ->
                    journal.runState(AgentWorkflowRunObservation("run_00000001", AgentWorkflowPhase.PROVISIONAL, "revision-one"))
                    journal.runState(AgentWorkflowRunObservation("run_00000001", AgentWorkflowPhase.EXHAUSTED, "revision-one"))
                    assertTrue(observed.await(5, TimeUnit.SECONDS))
                }
            }
        }
        assertTrue(bytes.toString(Charsets.UTF_8).contains(": provisional"))
        assertFalse(bytes.toString(Charsets.UTF_8).contains("revision-one"))
    }

    @Test
    fun `blocked console does not block journal producers or bounded observer close`() {
        val root = createTempDirectory("repair-cli-slow-console-")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val output = PrintStream(object : OutputStream() {
            override fun write(value: Int) {
                entered.countDown()
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Model noninterruptible console I/O. */ }
            }
        })
        val observer = RepairCliProgress(root, output)
        try {
            AgentProgressJournal(root, "repair").use { journal ->
                journal.runState(AgentWorkflowRunObservation("run_00000001", AgentWorkflowPhase.BUILD_VALIDATING))
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                val published = CountDownLatch(1)
                val producer = Thread {
                    repeat(1000) { journal.runState(AgentWorkflowRunObservation("run_00000001", AgentWorkflowPhase.PROVISIONAL)) }
                    published.countDown()
                }.apply { start() }
                assertTrue(published.await(5, TimeUnit.SECONDS))
                producer.join(1000)
                val started = System.nanoTime()
                observer.close()
                assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2))
            }
        } finally {
            release.countDown()
            observer.close()
            output.close()
        }
    }

    private fun event(sequence: Long, phase: String) = buildJsonObject {
        put("sequence", sequence); put("workflow", "repair"); put("kind", "workflow_run_state")
        put("phase", phase); put("workflowRunIdSha256", "a".repeat(64))
        put("text", "private peer text"); put("workflowRunId", "private raw ID")
    }

    private fun snapshot(next: Long, events: List<JsonObject>) = buildJsonObject {
        put("nextSequence", next); put("events", JsonArray(events))
    }
}
