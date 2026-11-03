package decompengine

import decompengine.jobs.FullRunJournal
import decompengine.jobs.FullRunEventReader
import decompengine.testing.recoveryMatrixTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import java.nio.file.Files
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(RecoveryMatrixEvidence::class)
class RunHistoryCliTest {
    @Test
    fun `explicit run lookup ignores unrelated incomplete directory`() {
        val root = recoveryMatrixTempDirectory("run-history-cli-")
        val runs = root.resolve(FullRunJournal.DIRECTORY)
        Files.createDirectory(runs)
        val validId = UUID.randomUUID().toString()
        val journal = FullRunJournal.create(root, validId, "reconstruction", 0)
        journal.close()
        Files.createDirectory(runs.resolve(UUID.randomUUID().toString()))

        assertEquals(journal.directory, resolveRunHistoryDirectory(root, validId))
        assertEquals(1, listRunHistory(root).second)
        assertNotNull(resolveRunHistoryDirectory(root, null))
    }

    @Test
    fun `terminal follow drains records appended after an earlier eof`() {
        val root = recoveryMatrixTempDirectory("run-history-follow-tail-")
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 4)
        val runId = journal.directory.fileName.toString()
        val observed = mutableListOf<kotlinx.serialization.json.JsonObject>()
        FullRunEventReader(journal.directory).use { reader ->
            assertNull(reader.next())
            journal.append(kotlinx.serialization.json.buildJsonObject {
                put("runId", runId); put("sequence", 4); put("kind", "workflow_phase"); put("phase", "completed")
            })
            journal.close()
            drainRunHistoryTail(reader, observed::add)
            assertEquals("closed", reader.verifyEnd().getValue("state").jsonPrimitive.content)
        }
        assertEquals(1, observed.size)
        assertEquals(4, observed.single().getValue("sequence").jsonPrimitive.content.toInt())
    }
}
