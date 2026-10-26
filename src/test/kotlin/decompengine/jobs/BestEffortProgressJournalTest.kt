package decompengine.jobs

import decompengine.agent.AgentWorkflowPhase
import decompengine.repair.RepairProgressProjection
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
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

    @Test
    fun `fixed warning mailbox coalesces both kinds behind a blocked sink`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val delivered = CountDownLatch(3)
        val lines = Collections.synchronizedList(mutableListOf<String>())
        val publisher = Executors.newSingleThreadExecutor()
        val mailbox = ProgressWarningMailbox { message ->
            if (entered.count > 0) {
                entered.countDown()
                while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Controlled blocked sink. */ }
            }
            lines.add(message)
            delivered.countDown()
        }
        try {
            mailbox.report(ProgressWarning.JOURNAL)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            publisher.submit {
                repeat(10_000) {
                    mailbox.report(ProgressWarning.JOURNAL)
                    mailbox.report(ProgressWarning.REPAIR)
                }
            }.get(5, TimeUnit.SECONDS)
            assertEquals(3L, delivered.count, "sink unexpectedly completed while held")
            release.countDown()
            assertTrue(delivered.await(5, TimeUnit.SECONDS))
            assertEquals(listOf(ProgressWarning.JOURNAL.message, ProgressWarning.JOURNAL.message,
                ProgressWarning.REPAIR.message), synchronized(lines) { lines.toList() })
        } finally {
            release.countDown()
            publisher.shutdownNow()
            mailbox.close()
            assertTrue(publisher.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `queued warnings preserve both workflow failures and another journal owner`() {
        val parent = java.nio.file.Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-warning").toAbsolutePath())
        val reports = createTempDirectory(parent, "mailbox-owner-")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val caller = Executors.newSingleThreadExecutor()
        val delivered = CountDownLatch(3)
        val lines = Collections.synchronizedList(mutableListOf<String>())
        val mailbox = ProgressWarningMailbox { message ->
            entered.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Controlled blocked sink. */ }
            lines.add(message)
            delivered.countDown()
        }
        try {
            mailbox.report(ProgressWarning.JOURNAL)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            AgentProgressJournal(reports, "reconstruction").use { owner ->
                val journalFailure = IllegalStateException("original journal workflow failure")
                val repairFailure = IllegalStateException("original repair workflow failure")
                caller.submit {
                    val observedJournal = assertFailsWith<IllegalStateException> {
                        BestEffortProgressJournal(reports, "reconstruction", onUnavailable = {
                            mailbox.report(ProgressWarning.JOURNAL)
                        }).use { progress ->
                            progress.phase(AgentWorkflowPhase.ANALYZING)
                            throw journalFailure
                        }
                    }
                    kotlin.test.assertSame(journalFailure, observedJournal)
                    val observedRepair = assertFailsWith<IllegalStateException> {
                        RepairProgressProjection(reports, onUnavailable = {
                            mailbox.report(ProgressWarning.REPAIR)
                        }).use { throw repairFailure }
                    }
                    kotlin.test.assertSame(repairFailure, observedRepair)
                    owner.phase(AgentWorkflowPhase.COMPLETED)
                }.get(5, TimeUnit.SECONDS)
            }
            assertTrue(AgentProgressJournal.read(reports) != null)
            AgentProgressJournal(reports, "reconstruction").use { it.phase(AgentWorkflowPhase.COMPLETED) }
            assertEquals(3L, delivered.count, "warning delivery escaped the controlled sink")
            release.countDown()
            assertTrue(delivered.await(5, TimeUnit.SECONDS))
            assertEquals(listOf(ProgressWarning.JOURNAL.message, ProgressWarning.JOURNAL.message,
                ProgressWarning.REPAIR.message), synchronized(lines) { lines.toList() })
        } finally {
            release.countDown()
            caller.shutdownNow()
            mailbox.close()
            assertTrue(caller.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `warning mailbox close preserves interruption without waiting for blocked output`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val outputFinished = CountDownLatch(1)
        val calls = AtomicInteger()
        val closer = Executors.newSingleThreadExecutor()
        val mailbox = ProgressWarningMailbox {
            calls.incrementAndGet()
            entered.countDown()
            while (release.count > 0) try { release.await() } catch (_: InterruptedException) { /* Noninterruptible console. */ }
            outputFinished.countDown()
        }
        try {
            mailbox.report(ProgressWarning.JOURNAL)
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            closer.submit {
                Thread.currentThread().interrupt()
                try {
                    mailbox.close()
                    assertTrue(Thread.currentThread().isInterrupted)
                } finally { Thread.interrupted() }
            }.get(5, TimeUnit.SECONDS)
            assertEquals(1L, outputFinished.count, "close waited for held output")
            mailbox.report(ProgressWarning.REPAIR)
        } finally {
            release.countDown()
            closer.shutdownNow()
            mailbox.close()
            assertTrue(closer.awaitTermination(5, TimeUnit.SECONDS))
        }
        assertTrue(outputFinished.await(5, TimeUnit.SECONDS))
        assertEquals(1, calls.get(), "a closed mailbox delivered another warning")
    }

    @Test
    fun `ordinary warning sink failure does not consume the next fixed kind`() {
        val rejected = CountDownLatch(1)
        val delivered = CountDownLatch(1)
        val lines = Collections.synchronizedList(mutableListOf<String>())
        ProgressWarningMailbox { message ->
            if (message == ProgressWarning.JOURNAL.message) {
                rejected.countDown()
                throw IllegalStateException("PRIVATE-warning-sink")
            }
            lines.add(message)
            delivered.countDown()
        }.use { mailbox ->
            mailbox.report(ProgressWarning.JOURNAL)
            assertTrue(rejected.await(5, TimeUnit.SECONDS))
            mailbox.report(ProgressWarning.REPAIR)
            assertTrue(delivered.await(5, TimeUnit.SECONDS))
        }
        assertEquals(listOf(ProgressWarning.REPAIR.message), synchronized(lines) { lines.toList() })
    }
}
