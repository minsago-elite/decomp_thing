package decompengine

import decompengine.jobs.FullRunJournal
import decompengine.jobs.FullRunEventReader
import decompengine.jobs.FullRunJournalFinalizationInProgressException
import decompengine.testing.recoveryMatrixTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
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

    @Test
    fun `follow retries a live finalization and still rejects its abandoned marker`() {
        val root = recoveryMatrixTempDirectory("run-history-follow-finalizing-")
        val fsyncCalls = AtomicInteger()
        val finalizationEntered = CountDownLatch(1)
        val allowFinalization = CountDownLatch(1)
        val journal = FullRunJournal.create(root, UUID.randomUUID().toString(), "reconstruction", 0,
            beforeMetadataDirectoryFsync = {
                if (fsyncCalls.incrementAndGet() == 2) {
                    finalizationEntered.countDown()
                    check(allowFinalization.await(5, TimeUnit.SECONDS))
                }
            })
        val closeFailure = AtomicReference<Throwable?>()
        val closer = Thread {
            try { journal.close() } catch (failure: Throwable) { closeFailure.set(failure) }
        }
        closer.start()
        assertTrue(finalizationEntered.await(5, TimeUnit.SECONDS), "journal should enter terminal metadata fsync")

        assertFailsWith<FullRunJournalFinalizationInProgressException> {
            FullRunJournal.metadata(journal.directory)
        }
        var retries = 0
        val reader = retryWhileFinalizing(
            pause = {
                retries++
                allowFinalization.countDown()
                Thread.sleep(10)
            },
        ) { FullRunEventReader(journal.directory) }
        reader.use {
            assertNull(it.next())
            assertEquals("closed", it.verifyEnd().getValue("state").jsonPrimitive.content)
        }
        closer.join(5_000)
        assertTrue(!closer.isAlive, "finalization should finish after the reader retries")
        assertNull(closeFailure.get())
        assertTrue(retries > 0, "follow should wait for an active finalization")

        Files.write(journal.directory.resolve(".finalization-in-progress"), byteArrayOf(1))
        assertFailsWith<IllegalArgumentException> { FullRunJournal.metadata(journal.directory) }
    }
}
