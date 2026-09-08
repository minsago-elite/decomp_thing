package decompengine.jobs

import kotlinx.serialization.json.*
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.WRITE
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.ZoneOffset
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.*

class AgentProgressJournalMaintenanceTest {
    private class MutableClock(var now: Instant = Instant.parse("2026-09-08T00:00:00Z")) : Clock() {
        override fun instant() = now
        override fun getZone(): ZoneId = ZoneOffset.UTC
        override fun withZone(zone: ZoneId): Clock = Clock.fixed(now, zone)
    }
    private class Fixture(terminal: Boolean = true) : AutoCloseable {
        val root = createTempDirectory("progress-maintenance-")
        val clock = MutableClock()
        val job = JobStore(root).createFromUpload("fixture.elf", elfFixture()).id
        var owner = WorkflowAttemptStore.open(root, clock)
        val run: WorkflowAttempt
        val directory: Path
        val journal: Path
        init {
            val view = owner.inspect(job) as WorkflowJobInspection.Available
            val queued = owner.create(job, view.snapshot.version, NewWorkflowAttempt(WorkflowKind.EXPLORE,
                WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
            val started = owner.transition(job, queued.runId, queued.version, WorkflowTransition.Start).attempt
            run = if (terminal) owner.transition(job, started.runId, started.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.NO_CHANGES)).attempt else started
            directory = root.resolve("$job/reports/runs/${run.runId}")
            journal = directory.resolve(AgentProgressJournal.FILE_NAME)
            AgentProgressJournal(directory, "explore").use { }
            clock.now = clock.now.plus(Duration.ofHours(24))
        }
        fun expire(protected: Boolean = false, fault: (ProgressRetentionFaultPoint) -> Unit = {}) =
            owner.expireProgressJournal(job, run.runId, protected, fault = fault)
        fun reopen() { owner.close(); owner = WorkflowAttemptStore.open(root, clock) }
        override fun close() { owner.close(); root.toFile().deleteRecursively() }
    }

    @Test fun `owned publication expires records and preserves durable metadata input and protected history`() = Fixture().use { f ->
        val original = Files.readAllBytes(f.journal)
        val metadata = Files.readAllBytes(f.root.resolve("${f.job}/workflow-state.json"))
        val input = Files.readAllBytes(f.root.resolve("${f.job}/input.elf"))
        assertEquals(ProgressRetentionResult.RETAINED, f.expire(protected = true))
        assertContentEquals(original, Files.readAllBytes(f.journal))
        assertEquals(ProgressRetentionResult.EXPIRED, f.expire())
        val expired = AgentProgressJournal.read(f.directory)!!
        assertTrue(expired.getValue("events").jsonArray.isEmpty())
        assertEquals("1", expired.getValue("historyDropped").jsonPrimitive.content)
        assertFalse(Files.exists(f.directory.resolve(AgentProgressJournalMaintenance.PENDING_FILE)))
        assertEquals(ProgressRetentionResult.RETAINED, f.expire())
        assertContentEquals(metadata, Files.readAllBytes(f.root.resolve("${f.job}/workflow-state.json")))
        assertContentEquals(input, Files.readAllBytes(f.root.resolve("${f.job}/input.elf")))
        f.reopen()
        assertEquals(f.run, f.owner.withAttemptSnapshot(f.job, f.run.runId) { it })
        assertEquals(ProgressRetentionResult.RETAINED, f.expire())
    }

    @Test fun `active attempts and absent journals do not acquire a retention publication`() {
        Fixture(terminal = false).use { f ->
            val original = Files.readAllBytes(f.journal)
            assertEquals(ProgressRetentionResult.RETAINED, f.expire())
            assertContentEquals(original, Files.readAllBytes(f.journal))
        }
        Fixture().use { f ->
            Files.delete(f.journal)
            assertEquals(ProgressRetentionResult.NO_JOURNAL, f.expire())
            assertEquals("RUN_NOT_FOUND", assertFailsWith<WorkflowStoreException> {
                f.owner.expireProgressJournal(f.job, "foreign", false)
            }.code)
            f.owner.close()
            assertEquals("STORE_CLOSED", assertFailsWith<WorkflowStoreException> { f.expire() }.code)
        }
    }

    @Test fun `interrupted publication converges after reopen at every durable boundary`() {
        for (point in ProgressRetentionFaultPoint.entries) Fixture().use { f ->
            val original = Files.readAllBytes(f.journal)
            val metadata = Files.readAllBytes(f.root.resolve("${f.job}/workflow-state.json"))
            assertFailsWith<SimulatedCrash>(point.name) {
                f.expire { if (it == point) throw SimulatedCrash() }
            }
            val current = Files.readAllBytes(f.journal)
            val parsed = AgentProgressJournal.decode(current)
            assertTrue(current.contentEquals(original) || parsed.containsKey("retentionExpiredAt"), point.name)
            f.reopen()
            val result = f.expire()
            assertTrue(result in setOf(ProgressRetentionResult.EXPIRED, ProgressRetentionResult.RETAINED), point.name)
            assertTrue(AgentProgressJournal.read(f.directory)!!.getValue("events").jsonArray.isEmpty())
            assertFalse(Files.exists(f.directory.resolve(AgentProgressJournalMaintenance.PENDING_FILE)), point.name)
            assertContentEquals(metadata, Files.readAllBytes(f.root.resolve("${f.job}/workflow-state.json")))
        }
    }

    @Test fun `ambiguous pending publication is preserved for explicit recovery`() = Fixture().use { f ->
        val original = Files.readAllBytes(f.journal)
        val pending = f.directory.resolve(AgentProgressJournalMaintenance.PENDING_FILE)
        Files.write(pending, original) // Two unexpired snapshots cannot establish a retention transaction.
        val failure = assertFailsWith<WorkflowStoreException> { f.expire() }
        assertEquals("PROGRESS_RETENTION_FAILED", failure.code)
        assertTrue(failure.outcomeUnknown)
        assertFalse(failure.message!!.contains(f.root.toString()))
        assertContentEquals(original, Files.readAllBytes(pending))
        assertContentEquals(original, Files.readAllBytes(f.journal))
    }

    @Test fun `publication IO failures preserve a valid journal and can be retried`() {
        for (point in listOf(ProgressRetentionFaultPoint.AFTER_TEMP_SYNC, ProgressRetentionFaultPoint.AFTER_EXCHANGE)) Fixture().use { f ->
            val original = Files.readAllBytes(f.journal)
            val failure = assertFailsWith<WorkflowStoreException> {
                f.expire { if (it == point) throw java.io.IOException("synthetic storage failure") }
            }
            assertEquals("PROGRESS_RETENTION_FAILED", failure.code)
            val current = Files.readAllBytes(f.journal)
            AgentProgressJournal.decode(current)
            if (point == ProgressRetentionFaultPoint.AFTER_TEMP_SYNC) {
                assertContentEquals(original, current)
                assertFalse(Files.exists(f.directory.resolve(AgentProgressJournalMaintenance.PENDING_FILE)))
            } else assertContentEquals(original, Files.readAllBytes(f.directory.resolve(AgentProgressJournalMaintenance.PENDING_FILE)))
            assertEquals(ProgressRetentionResult.EXPIRED, f.expire())
        }
    }

    @Test fun `live writer lease survives duplicate opens and excludes maintenance and another JVM`() = Fixture().use { f ->
        AgentProgressJournal(f.directory, "explore").use {
            assertFailsWith<IllegalArgumentException> { AgentProgressJournal(f.directory, "explore") }
            assertEquals(ProgressRetentionResult.WRITER_ACTIVE, f.expire())
            val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), AgentProgressJournalLockProbe::class.java.name,
                f.directory.resolve("agent-progress.lock").toString()).redirectErrorStream(true).start()
            try {
                assertTrue(process.waitFor(10, TimeUnit.SECONDS))
                assertEquals(0, process.exitValue(), process.inputStream.readBytes().decodeToString())
            } finally { process.destroyForcibly() }
        }
        assertEquals(ProgressRetentionResult.EXPIRED, f.expire())
    }

    @Test fun `maintenance waits for the durable snapshot read transaction`() = Fixture().use { f ->
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val requested = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val reader = executor.submit<ByteArray> {
                f.owner.withAttemptSnapshot(f.job, f.run.runId) {
                    entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); Files.readAllBytes(f.journal)
                }
            }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            val expiry = executor.submit<ProgressRetentionResult> { requested.countDown(); f.expire() }
            assertTrue(requested.await(3, TimeUnit.SECONDS))
            assertFailsWith<java.util.concurrent.TimeoutException> { expiry.get(100, TimeUnit.MILLISECONDS) }
            release.countDown()
            assertFalse(AgentProgressJournal.decode(reader.get(3, TimeUnit.SECONDS)).getValue("events").jsonArray.isEmpty())
            assertEquals(ProgressRetentionResult.EXPIRED, expiry.get(3, TimeUnit.SECONDS))
        } finally {
            release.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
        }
    }

    @Test fun `linked journal entries are denied without changing their owned fixture target`() = Fixture().use { f ->
        val original = Files.readAllBytes(f.journal)
        val other = f.root.resolve("owned-marker.json")
        Files.write(other, original)
        Files.delete(f.journal)
        Files.createSymbolicLink(f.journal, other)
        assertEquals("PROGRESS_RETENTION_FAILED", assertFailsWith<WorkflowStoreException> { f.expire() }.code)
        assertContentEquals(original, Files.readAllBytes(other))
        Files.delete(f.journal)
        Files.createLink(f.journal, other)
        assertEquals("PROGRESS_RETENTION_FAILED", assertFailsWith<WorkflowStoreException> { f.expire() }.code)
        assertContentEquals(original, Files.readAllBytes(other))
    }

    private class SimulatedCrash : Error("synthetic interruption")
}

/** Own-fixture lock probe only; no workflow or external target is involved. */
object AgentProgressJournalLockProbe {
    @JvmStatic fun main(args: Array<String>) {
        FileChannel.open(Path.of(args.single()), WRITE).use { channel ->
            val lock = channel.tryLock()
            if (lock != null) { lock.release(); error("live writer lock was lost") }
        }
    }
}
