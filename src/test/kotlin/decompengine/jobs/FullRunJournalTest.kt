package decompengine.jobs

import decompengine.agent.AgentWorkflowPhase
import java.nio.file.Files
import java.util.UUID
import kotlinx.serialization.json.*
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.*

class FullRunJournalTest {
    @Test
    fun `full run history survives display eviction and redacts diagnostics`() {
        val root = createTempDirectory("full-run-")
        lateinit var directory: java.nio.file.Path
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumEvents = 8,
            maximumQueuedEvents = 2, recordFullRun = true).use { journal ->
            directory = journal.fullRunDirectory!!
            repeat(40) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING, "module-$it") }
            journal.diagnostic("failure private-credential")
            journal.phase(AgentWorkflowPhase.UNRESOLVED)
        }
        val events = mutableListOf<JsonObject>()
        FullRunEventReader(directory).use { reader ->
            while (true) events += reader.next() ?: break
            assertEquals(JsonPrimitive(true), reader.verifyEnd()["complete"])
        }
        assertEquals(43, events.size)
        assertEquals(events.indices.map(Int::toLong), events.map { it.getValue("sequence").jsonPrimitive.long })
        assertFalse(directory.resolve("events.jsonl").readText().contains("private-credential"))
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
