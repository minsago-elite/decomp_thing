package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/** Deterministic journal-publication read-failure control; the historical appended-SSE cause (#514) remains unproved. */
class WebProgressPublicationReadTest {
    private fun withJournal(block: (Path, Path) -> Unit) {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-fixtures")), "web-progress-publication-")
        try {
            val journal = Files.createDirectories(root.resolve("job/reports/runs/run_fixture")).resolve(AgentProgressJournal.FILE_NAME)
            Files.writeString(journal, "{\"generation\":1}")
            block(root, journal)
        } finally { root.toFile().deleteRecursively() }
    }

    private fun republish(journal: Path, text: String) {
        val temporary = journal.resolveSibling("publication.next")
        Files.writeString(temporary, text)
        Files.move(temporary, journal, ATOMIC_MOVE, REPLACE_EXISTING)
    }

    @Test fun `an atomic republication during a pinned read refuses that read and a re-read observes the new journal`() = withJournal { root, journal ->
        val relative = "job/reports/runs/run_fixture/${AgentProgressJournal.FILE_NAME}"
        // The writer's rename lands after the descriptor was read but before its path binding is revalidated.
        assertFailsWith<IllegalArgumentException> {
            readStableRegularFile(root, relative, 1024, afterRead = { republish(journal, "{\"generation\":2}") })
        }
        val calls = AtomicInteger()
        val bytes = readAcrossJournalPublication {
            val hook: (() -> Unit)? = if (calls.incrementAndGet() == 1) ({ republish(journal, "{\"generation\":3}") }) else null
            readStableRegularFile(root, relative, 1024, afterRead = hook).bytes
        }
        assertEquals(2, calls.get())
        assertEquals("{\"generation\":3}", bytes.decodeToString())
    }

    @Test fun `re-reads are bounded and the final failure is reported unchanged`() {
        val calls = AtomicInteger()
        val failure = assertFailsWith<IllegalArgumentException> {
            readAcrossJournalPublication<ByteArray> { calls.incrementAndGet(); throw IllegalArgumentException("binding changed ${calls.get()}") }
        }
        assertEquals(JOURNAL_READ_ATTEMPTS, calls.get())
        assertEquals("binding changed $JOURNAL_READ_ATTEMPTS", failure.message)
        calls.set(0)
        assertFailsWith<IllegalStateException> {
            readAcrossJournalPublication<ByteArray>(attempts = 1) { calls.incrementAndGet(); throw IllegalStateException("missing") }
        }
        assertEquals(1, calls.get())
        assertFailsWith<IllegalArgumentException> { readAcrossJournalPublication(attempts = 0) { 1 } }
        assertFailsWith<IllegalArgumentException> { readAcrossJournalPublication(attempts = JOURNAL_READ_ATTEMPTS + 1) { 1 } }
    }

    @Test fun `budget refusals and interruption are never retried`() {
        val calls = AtomicInteger()
        assertFailsWith<RepairBudgetExceededException> {
            readAcrossJournalPublication<ByteArray> { calls.incrementAndGet(); throw RepairBudgetExceededException("over limit") }
        }
        assertEquals(1, calls.get())
        calls.set(0)
        try {
            assertFailsWith<IllegalArgumentException> {
                readAcrossJournalPublication<ByteArray> {
                    calls.incrementAndGet(); Thread.currentThread().interrupt(); throw IllegalArgumentException("interrupted read")
                }
            }
            assertEquals(1, calls.get())
        } finally { Thread.interrupted() }
    }
}
