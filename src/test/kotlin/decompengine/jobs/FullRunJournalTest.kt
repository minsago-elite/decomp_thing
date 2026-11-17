package decompengine.jobs

import decompengine.agent.AgentWorkflowPhase
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import org.junit.jupiter.api.extension.ExtendWith
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class FullRunJournalTest {
    @Test
    fun `full history fsync runs away from producers and bounded overflow is explicit`() {
        val root = createTempDirectory("run-writer-isolation-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val writer = FullRunJournalWriter(journal, maximumQueuedEvents = 2, beforeAppend = {
            entered.countDown()
            release.await(5, TimeUnit.SECONDS)
        })
        val id = journal.directory.fileName.toString()
        try {
            writer.append(event(id, 0))
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val producerReturned = CountDownLatch(1)
            Thread { writer.append(event(id, 1)); producerReturned.countDown() }.start()
            assertTrue(producerReturned.await(1, TimeUnit.SECONDS), "producer waited on a blocked history write")
            writer.append(event(id, 2))
            writer.append(event(id, 3)) // bounded queue overflow; the record is not silently claimed complete
        } finally {
            release.countDown()
        }
        val closeFailure = assertFailsWith<IllegalStateException> { writer.close() }
        assertEquals("full run journal recording failed", closeFailure.message)
        val metadata = FullRunJournal.metadata(journal.directory)
        assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), metadata.getValue("complete"))
        FullRunEventReader(journal.directory).use { reader ->
            var count = 0
            while (reader.next() != null) count++
            assertEquals(3, count)
            assertEquals("logging-failed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
    }

    @Test
    fun `writer drains a bounded FIFO batch and closes with every admitted event durable`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-batch")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0)
        val id = journal.directory.fileName.toString()
        val firstAppend = CountDownLatch(1)
        val release = CountDownLatch(1)
        val blockedOnce = java.util.concurrent.atomic.AtomicBoolean()
        val batchSizes = java.util.concurrent.CopyOnWriteArrayList<Int>()
        val writer = FullRunJournalWriter(journal,
            beforeAppend = {
                if (blockedOnce.compareAndSet(false, true)) {
                    firstAppend.countDown()
                    assertTrue(release.await(5, TimeUnit.SECONDS))
                }
            },
            afterBatchWritten = { batchSizes.add(it) },
        )
        assertTrue(writer.append(event(id, 0)))
        assertTrue(firstAppend.await(5, TimeUnit.SECONDS))
        repeat(40) { sequence -> assertTrue(writer.append(event(id, sequence.toLong() + 1))) }
        release.countDown()

        writer.close()
        assertEquals(41, batchSizes.sum())
        assertTrue(batchSizes.size < 41, "queued events were not written in batches")
        assertTrue(batchSizes.all { it in 1..64 })
        FullRunEventReader(journal.directory).use { reader ->
            repeat(41) { sequence -> assertEquals(sequence, reader.next()!!.getValue("sequence").jsonPrimitive.int) }
            assertNull(reader.next())
            val terminal = reader.verifyEnd()
            assertEquals("closed", terminal.getValue("state").jsonPrimitive.content)
            assertEquals(JsonPrimitive(true), terminal.getValue("complete"))
        }
    }

    @Test
    fun `invalid event in a batch writes no prefix and cannot claim completeness`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-invalid-batch")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val id = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, id, "reconstruction", 0)

        assertFailsWith<IllegalArgumentException> {
            journal.appendBatch(listOf(event(id, 0), event(id, 2)))
        }
        journal.close()

        val metadata = FullRunJournal.metadata(journal.directory)
        assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), metadata.getValue("complete"))
        assertEquals(0L, metadata.getValue("eventCount").jsonPrimitive.long)
        assertEquals(0, Files.size(journal.directory.resolve("events.jsonl")))
        FullRunEventReader(journal.directory).use { reader ->
            assertNull(reader.next())
            assertEquals("logging-failed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
    }

    @Test
    fun `append failure is reported after bounded writer drains and marks history incomplete`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-append-failure")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0)
        val writer = FullRunJournalWriter(journal, beforeAppend = { error("private append detail") })
        assertTrue(writer.append(event(journal.directory.fileName.toString(), 0)))

        val failure = assertFailsWith<IllegalStateException> { writer.close() }
        assertEquals("full run journal recording failed", failure.message)
        assertEquals("logging-failed", FullRunJournal.metadata(journal.directory)
            .getValue("state").jsonPrimitive.content)
        assertFalse(journal.directory.resolve("run.json").toFile().readText().contains("private append detail"))
        FullRunEventReader(journal.directory).use { reader ->
            assertNull(reader.next())
            assertEquals("logging-failed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
    }

    @Test
    fun `finalization failure reaches close and never claims complete history`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-finalize-failure")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0)
        val id = journal.directory.fileName.toString()
        val writer = FullRunJournalWriter(journal, beforeFinalize = { error("private finalization detail") })
        assertTrue(writer.append(event(id, 0)))

        val failure = assertFailsWith<IllegalStateException> { writer.close() }
        assertEquals("full run journal recording failed", failure.message)
        val metadata = FullRunJournal.metadata(journal.directory)
        assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), metadata.getValue("complete"))
        FullRunEventReader(journal.directory).use { reader ->
            assertEquals(0, reader.next()!!.getValue("sequence").jsonPrimitive.int)
            assertEquals("logging-failed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
    }

    @Test
    fun `post replacement directory fsync failure replaces readable complete metadata with failure status`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-directory-fsync-failure")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val directoryFsyncs = java.util.concurrent.atomic.AtomicInteger()
        val failure = IllegalStateException("injected post-replacement directory fsync failure")
        val id = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, id, "reconstruction", 0,
            beforeMetadataDirectoryFsync = {
                if (directoryFsyncs.incrementAndGet() == 2) throw failure
            })
        val writer = FullRunJournalWriter(journal)
        assertTrue(writer.append(event(id, 0)))

        val closeFailure = assertFailsWith<IllegalStateException> { writer.close() }
        assertEquals("full run journal recording failed", closeFailure.message)
        assertSame(failure, closeFailure.cause)
        val metadata = FullRunJournal.metadata(journal.directory)
        assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), metadata.getValue("complete"))
        FullRunEventReader(journal.directory).use { reader ->
            assertEquals(0L, reader.next()!!.getValue("sequence").jsonPrimitive.long)
            assertEquals("logging-failed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
    }

    @Test
    fun `failed fallback leaves a durable veto that readers reject`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-fallback-failure")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val directoryFsyncs = java.util.concurrent.atomic.AtomicInteger()
        val metadataWrites = java.util.concurrent.atomic.AtomicInteger()
        val id = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, id, "reconstruction", 0,
            beforeMetadataDirectoryFsync = {
                if (directoryFsyncs.incrementAndGet() == 2) error("injected close directory fsync failure")
            },
            beforeMetadataWrite = {
                if (metadataWrites.incrementAndGet() == 3) error("injected fallback pre-write failure")
            })
        journal.append(event(id, 0))

        assertFailsWith<IllegalStateException> { journal.close() }
        assertTrue(Files.exists(journal.directory.resolve(".finalization-in-progress")))
        // The first close publication is visible but indeterminate; the veto prevents replay or
        // metadata consumers from interpreting it as a successful complete history.
        assertTrue(journal.directory.resolve("run.json").readText().contains("\"complete\":true"))
        assertFailsWith<IllegalArgumentException> { FullRunJournal.metadata(journal.directory) }
        assertFailsWith<IllegalArgumentException> { FullRunEventReader(journal.directory) }
    }

    @Test
    fun `interrupt during writer finalization is cleared for fallback then restored`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-interrupt")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val directoryFsyncs = java.util.concurrent.atomic.AtomicInteger()
        val id = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, id, "reconstruction", 0,
            beforeMetadataDirectoryFsync = {
                if (directoryFsyncs.incrementAndGet() == 2) error("injected close directory fsync failure")
            })
        journal.append(event(id, 0))
        try {
            Thread.currentThread().interrupt()
            assertFailsWith<IllegalStateException> { journal.close() }
            assertTrue(Thread.currentThread().isInterrupted, "journal close must restore interruption")
            val metadata = FullRunJournal.metadata(journal.directory)
            assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
            assertFalse(metadata.getValue("complete").jsonPrimitive.boolean)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `parent directory fsync failures cannot create a successful complete history`() {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/run-writer-parent-fsync")
            .toAbsolutePath())
        val root = createTempDirectory(parent, "run-writer-")
        val id = UUID.randomUUID().toString()
        assertFailsWith<IllegalStateException> {
            FullRunJournal.create(root, id, "reconstruction", 0,
                beforeParentDirectoryFsync = { error("injected parent directory fsync failure") })
        }

        val runs = root.resolve(FullRunJournal.DIRECTORY)
        assertTrue(Files.isDirectory(runs))
        assertFalse(Files.exists(runs.resolve(id)))
        val succeedingId = UUID.randomUUID().toString()
        assertFailsWith<IllegalStateException> {
            FullRunJournal.create(root, succeedingId, "reconstruction", 0,
                beforeParentDirectoryFsync = { path ->
                    if (path == runs) error("injected run-history entry fsync failure")
                })
        }
        assertTrue(Files.isDirectory(runs.resolve(succeedingId)))
        assertFalse(Files.exists(runs.resolve(succeedingId).resolve("run.json")))
    }

    @Test
    fun `full run history survives display eviction and redacts diagnostics`() {
        val root = createTempDirectory("full-run-")
        lateinit var directory: java.nio.file.Path
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumEvents = 8,
            maximumQueuedEvents = 2, recordFullRun = true).use { journal ->
            directory = journal.fullRunDirectory!!
            repeat(40) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING, "module-$it") }
            journal.checkpointReused("private-module-id", "a".repeat(64))
            journal.diagnostic("failure private-credential")
            journal.phase(AgentWorkflowPhase.UNRESOLVED)
        }
        val events = mutableListOf<JsonObject>()
        FullRunEventReader(directory).use { reader ->
            while (true) events += reader.next() ?: break
            assertEquals(JsonPrimitive(true), reader.verifyEnd()["complete"])
        }
        assertEquals(44, events.size)
        assertEquals(events.indices.map(Int::toLong), events.map { it.getValue("sequence").jsonPrimitive.long })
        assertFalse(directory.resolve("events.jsonl").readText().contains("private-credential"))
        val reuse = events.single { it.getValue("kind").jsonPrimitive.content == "module_checkpoint_reused" }
        assertEquals("a".repeat(64), reuse.getValue("sourceSha256").jsonPrimitive.content)
        assertEquals(64, reuse.getValue("moduleIdSha256").jsonPrimitive.content.length)
        assertFalse(directory.resolve("events.jsonl").readText().contains("private-module-id"))
        assertTrue(AgentProgressJournal.read(root)!!.getValue("truncated").jsonPrimitive.boolean)
    }

    @Test
    fun `new attempts retain independent logs while continuing global sequence`() {
        val root = createTempDirectory("run-attempts-")
        val directories = (1..2).map {
            var directory: java.nio.file.Path? = null
            AgentProgressJournal(root, "reconstruction", recordFullRun = true).use { journal ->
                directory = journal.fullRunDirectory
                journal.phase(AgentWorkflowPhase.UNRESOLVED)
            }
            directory!!
        }
        assertNotEquals(directories[0], directories[1])
        directories.forEachIndexed { index, directory ->
            FullRunEventReader(directory).use { reader ->
                assertEquals((index * 2).toLong(), reader.next()!!.getValue("sequence").jsonPrimitive.long)
                assertNotNull(reader.next())
                assertNull(reader.next())
                reader.verifyEnd()
            }
        }
    }

    @Test
    fun `tail reader sees appended records and replay rejects tampering`() {
        val root = createTempDirectory("run-tail-")
        val id = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, id, "reconstruction", 5)
        val directory = journal.directory
        FullRunEventReader(directory).use { reader ->
            assertNull(reader.next())
            journal.append(event(id, 5))
            assertEquals(5, reader.next()!!.getValue("sequence").jsonPrimitive.int)
            assertNull(reader.next())
            journal.append(event(id, 6))
            journal.close()
            assertEquals(6, reader.next()!!.getValue("sequence").jsonPrimitive.int)
            assertNull(reader.next())
            reader.verifyEnd()
        }
        val path = directory.resolve("events.jsonl")
        path.writeText(path.readText().replace("\"sequence\":5", "\"sequence\":7"))
        FullRunEventReader(directory).use { reader -> assertFailsWith<IllegalArgumentException> { reader.next() } }
    }

    @Test
    fun `truncated closed histories and linked records fail replay`() {
        val root = createTempDirectory("run-corrupt-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0)
        journal.append(event(journal.directory.fileName.toString(), 0))
        journal.close()
        val path = journal.directory.resolve("events.jsonl")
        val bytes = Files.readAllBytes(path)
        Files.write(path, bytes.dropLast(1).toByteArray())
        FullRunEventReader(journal.directory).use { reader ->
            assertNull(reader.next())
            assertFailsWith<IllegalArgumentException> { reader.verifyEnd() }
        }
        Files.delete(path)
        Files.createSymbolicLink(path, root.resolve("elsewhere"))
        assertFailsWith<IllegalArgumentException> { FullRunEventReader(journal.directory) }
    }

    @Test
    fun `quota exhaustion is explicit rather than silent history eviction`() {
        val root = createTempDirectory("run-quota-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0, 4096)
        val id = journal.directory.fileName.toString()
        assertFailsWith<IllegalArgumentException> {
            repeat(100) { journal.append(event(id, it.toLong())) }
        }
        journal.close()
        val metadata = FullRunJournal.metadata(journal.directory)
        assertEquals("logging-failed", metadata.getValue("state").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), metadata["complete"])
    }

    private fun event(id: String, sequence: Long) = buildJsonObject {
        put("runId", id)
        put("sequence", sequence)
        put("kind", "workflow_phase")
        put("phase", "unresolved")
    }
}
