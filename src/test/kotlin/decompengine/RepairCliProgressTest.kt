package decompengine

import decompengine.agent.*
import decompengine.jobs.AgentProgressJournal
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

class RepairCliProgressTest {
    @Test
    fun `reconstruction terminal display drains owned callbacks without retained file reads`(): Unit {
        val parent = Files.createDirectories(Path.of("build/test-tmp/reconstruction-no-read"))
        for (phase in listOf(AgentWorkflowPhase.COMPLETED, AgentWorkflowPhase.UNRESOLVED, AgentWorkflowPhase.FAILED)) {
            val root = createTempDirectory(parent, "journal-")
            val bytes = ByteArrayOutputStream()
            val reads = java.util.concurrent.atomic.AtomicInteger()
            PrintStream(bytes, true, Charsets.UTF_8).use { output ->
                ReconstructionCliProgress.open(root, emptyList(), output, readSnapshot = {
                    reads.incrementAndGet()
                    error("reconstruction console must not depend on retained snapshot latency")
                }).use { progress ->
                    progress.phase(AgentWorkflowPhase.ANALYZING)
                    progress.phase(phase)
                    progress.close()
                    val lines = bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.toList()
                    assertEquals(listOf("reconstruction: analyzing", "reconstruction: ${phase.name.lowercase()}"), lines)
                    assertEquals(0, reads.get())
                }
            }
            val snapshot = assertNotNull(AgentProgressJournal.read(root))
            assertTrue(snapshot.getValue("events").jsonArray.any {
                it.jsonObject["phase"]?.jsonPrimitive?.content == phase.name.lowercase()
            })
        }
        assertBoundedReconstructionMailbox(parent)
    }

    private fun assertBoundedReconstructionMailbox(parent: Path) {
        val root = createTempDirectory(parent, "bounded-mailbox-")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val published = CountDownLatch(1)
        val terminalPrinted = CountDownLatch(1)
        val first = java.util.concurrent.atomic.AtomicBoolean(true)
        val reads = java.util.concurrent.atomic.AtomicInteger()
        val failure = AtomicReference<Throwable?>()
        val bytes = ByteArrayOutputStream()
        val output = PrintStream(object : OutputStream() {
            override fun write(value: Int) {
                if (first.compareAndSet(true, false)) {
                    entered.countDown()
                    while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Controlled blocked console. */ }
                }
                bytes.write(value)
                if (value == '\n'.code && bytes.toString(Charsets.UTF_8).lineSequence().any {
                    it == "reconstruction: completed"
                }) terminalPrinted.countDown()
            }
        }, true, Charsets.UTF_8)
        val progress = ReconstructionCliProgress.open(root, emptyList(), output, readSnapshot = {
            reads.incrementAndGet()
            error("reconstruction console must not read retained history")
        })
        val producer = Thread {
            try {
                progress.phase(AgentWorkflowPhase.ANALYZING)
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                repeat(64) { progress.phase(AgentWorkflowPhase.BUILD_VALIDATING) }
                progress.phase(AgentWorkflowPhase.COMPLETED)
                published.countDown()
            } catch (problem: Throwable) { failure.set(problem) }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(published.await(5, TimeUnit.SECONDS), "blocked console stalled phase capture")
            assertNull(failure.get())
            release.countDown()
            assertTrue(terminalPrinted.await(5, TimeUnit.SECONDS))
            producer.join(5000)
            progress.close()
            assertEquals(0, reads.get())
            val lines = bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.toList()
            assertEquals(listOf("reconstruction: analyzing", "reconstruction progress omitted 33 older phase update(s)") +
                List(31) { "reconstruction: build validating" } + "reconstruction: completed", lines)
            val snapshot = assertNotNull(AgentProgressJournal.read(root))
            assertEquals(67L, snapshot.getValue("nextSequence").jsonPrimitive.long)
            assertEquals(0L, snapshot.getValue("queueDropped").jsonPrimitive.long)
            assertEquals(0L, snapshot.getValue("historyDropped").jsonPrimitive.long)
        } finally {
            release.countDown()
            producer.join(5000)
            progress.close()
            output.close()
        }
    }

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

    @Test
    fun `reconstruction cursor bounds phases and rejects unrelated or private observations`() {
        fun phase(sequence: Long, name: String) = JsonObject(event(sequence, name).toMutableMap().apply {
            put("workflow", JsonPrimitive("reconstruction"))
            put("kind", JsonPrimitive("workflow_phase"))
            put("runId", JsonPrimitive("owned-run"))
        })
        val cursor = RepairCliProgressCursor(null, CliProgressWorkflow.RECONSTRUCTION)
        val records = (0L..49).map { phase(it, "build_validating") } + listOf(
            event(50, "accepted"),
            JsonObject(phase(51, "accepted").toMutableMap().apply { put("kind", JsonPrimitive("workflow_run_state")) }),
            phase(52, "private arbitrary phase"),
            JsonObject(phase(53, "completed").toMutableMap().apply { put("kind", JsonPrimitive("task_output")) }),
        )
        val lines = cursor.advance(snapshot(54, records), "owned-run")
        assertEquals(33, lines.size)
        assertEquals("reconstruction progress omitted 18 older phase update(s)", lines.first())
        assertTrue(lines.drop(1).all { it == "reconstruction: build validating" })
        assertFalse(lines.joinToString().contains("private"))
        assertTrue(cursor.advance(snapshot(54, records), "owned-run").isEmpty())
        val restarted = cursor.advance(snapshot(1, listOf(phase(0, "analyzing"))), "owned-run")
        assertTrue(restarted.first().contains("history restarted"))
        assertEquals("reconstruction: analyzing", restarted.last())
        val retained = RepairCliProgressCursor(snapshot(54, records), CliProgressWorkflow.RECONSTRUCTION)
        assertEquals(listOf("reconstruction: completed"), retained.advance(snapshot(55, listOf(phase(54, "completed"))), "owned-run"))
    }

    @Test
    fun `reconstruction journal production and close survive a blocked console`() {
        assertReconstructionConsoleBackpressure(unavailable = false)
    }

    @Test
    fun `reconstruction unavailable warning preserves workflow failure with a blocked console`() {
        assertReconstructionConsoleBackpressure(unavailable = true)
    }

    @Test
    fun `reconstruction close drains terminal phases and an immediate unavailable warning`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp"))
        for (phase in listOf(AgentWorkflowPhase.COMPLETED, AgentWorkflowPhase.UNRESOLVED, AgentWorkflowPhase.FAILED)) {
            val root = Files.createTempDirectory(parent, "reconstruction-terminal-")
            val bytes = ByteArrayOutputStream()
            PrintStream(bytes, true, Charsets.UTF_8).use { output ->
                withReconstructionCliProgress(root, output = output) { progress ->
                    progress.phase(phase)
                    if (phase == AgentWorkflowPhase.FAILED) {
                        progress.close()
                        assertTrue(bytes.toString(Charsets.UTF_8).contains("reconstruction: failed"))
                    }
                }
            }
            assertTrue(bytes.toString(Charsets.UTF_8).contains("reconstruction: ${phase.name.lowercase()}"))
        }
        val root = Files.createTempDirectory(parent, "reconstruction-unavailable-")
        val bytes = ByteArrayOutputStream()
        AgentProgressJournal(root, "reconstruction").use {
            PrintStream(bytes, true, Charsets.UTF_8).use { output ->
                withReconstructionCliProgress(root, output = output) { }
            }
        }
        assertEquals(
            listOf("Progress reporting is unavailable; workflow results remain authoritative."),
            bytes.toString(Charsets.UTF_8).lineSequence().filter { it.isNotEmpty() }.toList(),
        )
    }

    @Test
    fun `reconstruction cursor requires the acquired journal run and ignores other invocations`() {
        fun phase(sequence: Long, run: String, name: String) = buildJsonObject {
            put("sequence", sequence); put("workflow", "reconstruction"); put("kind", "workflow_phase")
            put("runId", run); put("phase", name); put("text", "private peer content")
        }
        val cursor = RepairCliProgressCursor(null, CliProgressWorkflow.RECONSTRUCTION)
        val first = snapshot(3, listOf(
            phase(0, "earlier-run", "failed"),
            phase(1, "owned-run", "analyzing"),
            phase(2, "other-run", "completed"),
        ))
        assertTrue(cursor.advance(first).isEmpty())
        assertEquals(listOf("reconstruction: analyzing"), cursor.advance(first, "owned-run"))
        assertTrue(cursor.advance(snapshot(4, listOf(phase(3, "other-run", "unresolved"))), "owned-run").isEmpty())
        assertEquals(
            listOf("reconstruction: completed"),
            cursor.advance(snapshot(5, listOf(phase(4, "owned-run", "completed"))), "owned-run"),
        )
    }

    private fun assertReconstructionConsoleBackpressure(unavailable: Boolean) {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "reconstruction-console-")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val published = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val sentinel = IllegalStateException("workflow sentinel")
        val output = PrintStream(object : OutputStream() {
            override fun write(value: Int) {
                entered.countDown()
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Noninterruptible console. */ }
            }
        })
        val owner = if (unavailable) AgentProgressJournal(root, "reconstruction") else null
        val producer = Thread {
            try {
                withReconstructionCliProgress(root, output = output) { progress ->
                    progress.phase(AgentWorkflowPhase.ANALYZING)
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    if (!unavailable) repeat(1000) { progress.phase(AgentWorkflowPhase.BUILD_VALIDATING) }
                    published.countDown()
                    if (unavailable) throw sentinel
                }
            } catch (caught: Throwable) {
                failure.set(caught)
            } finally {
                finished.countDown()
            }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS), "console observer did not reach the blocked output")
            assertTrue(published.await(5, TimeUnit.SECONDS), "blocked output stalled workflow progress")
            assertTrue(finished.await(7, TimeUnit.SECONDS), "blocked output stalled progress close")
            if (unavailable) assertSame(sentinel, failure.get()) else assertNull(failure.get())
            owner?.phase(AgentWorkflowPhase.COMPLETED)
        } finally {
            release.countDown()
            producer.join(5000)
            owner?.close()
            output.close()
        }
        assertNotNull(AgentProgressJournal.read(root))
        AgentProgressJournal(root, "reconstruction").use { it.phase(AgentWorkflowPhase.COMPLETED) }
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
