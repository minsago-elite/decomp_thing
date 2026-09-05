package decompengine.jobs

import java.io.IOException
import java.nio.file.Files
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readBytes
import kotlin.test.*

class StagedJobUploadTest {
    @Test fun `complete job becomes visible only after input and metadata are durable`() = withRoot { root ->
        val store = JobStore(root)
        val bytes = elfFixture() + ByteArray(200000) { (it % 251).toByte() }
        val publisher = StagedJobUpload(root) { point ->
            if (point != UploadPublishPoint.AFTER_RENAME) assertTrue(store.jobIds().isEmpty())
            else assertEquals(1, store.jobIds().size)
        }
        val result = publisher.publish { output -> output.write(bytes); "sample.elf" }
        assertEquals(result.job, store.get(result.job.id))
        assertContentEquals(bytes, result.job.binaryPath.readBytes())
        assertEquals("uploaded", result.job.status)
        assertEquals(MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }, result.inputSha256)
        assertEquals(listOf(result.job.id), names(root))
        assertTrue(Files.isExecutable(result.job.binaryPath))
    }

    @Test fun `invalid headers interrupted streams and pre-rename faults never expose a partial job`() = withRoot { root ->
        assertFailsWith<InvalidUploadException> { StagedJobUpload(root).publish { it.write(byteArrayOf(1, 2)); "invalid.elf" } }
        assertTrue(names(root).isEmpty())
        assertFailsWith<IOException> { StagedJobUpload(root).publish { it.write(elfFixture()); throw IOException("inert interrupted stream") } }
        assertTrue(names(root).isEmpty())
        for (point in UploadPublishPoint.entries.filter { it != UploadPublishPoint.AFTER_RENAME }) {
            assertFailsWith<IOException> { StagedJobUpload(root) { if (it == point) throw IOException("inert publication fault") }
                .publish { it.write(elfFixture()); "valid.elf" } }
            assertTrue(names(root).isEmpty(), point.name)
        }
    }

    @Test fun `post-rename failure retains one complete job and reports uncertain publication`() = withRoot { root ->
        val failure = assertFailsWith<UploadPublicationUncertain> {
            StagedJobUpload(root) { if (it == UploadPublishPoint.AFTER_RENAME) throw IOException("inert post-rename fault") }
                .publish { it.write(elfFixture()); "retained.elf" }
        }
        val job = JobStore(root).get(failure.jobId)
        assertEquals("retained.elf", job.filename)
        assertContentEquals(elfFixture(), job.binaryPath.readBytes())
        assertEquals(listOf(job.id), names(root))
    }

    @Test fun `identical deliberate uploads create distinct jobs and display names cannot select paths`() = withRoot { root ->
        val publisher = StagedJobUpload(root)
        val first = publisher.publish { it.write(elfFixture()); "same.elf" }
        val second = publisher.publish { it.write(elfFixture()); "same.elf" }
        assertNotEquals(first.job.id, second.job.id)
        assertEquals(first.inputSha256, second.inputSha256)
        assertFailsWith<IllegalArgumentException> { publisher.publish { it.write(elfFixture()); "../elsewhere" } }
        assertEquals(setOf(first.job.id, second.job.id), names(root).toSet())
    }

    @Test fun `receipt replay survives restart and later job mutation while changed intent conflicts`() = withRoot { root ->
        val key = "fixture_upload_key_0001"
        val first = StagedJobUpload(root).publish(key) { it.write(elfFixture()); "original.elf" }
        JobStore(root).updateStatus(first.job.id, "complete", "later outcome")
        val replay = StagedJobUpload(root).publish(key) { it.write(elfFixture()); "original.elf" }
        assertTrue(replay.replayed)
        assertEquals(first.job, replay.job)
        assertEquals("complete", JobStore(root).get(first.job.id).status)
        assertFailsWith<UploadIdempotencyConflict> { StagedJobUpload(root).publish(key) { it.write(elfFixture()); "different.elf" } }
        assertFailsWith<UploadIdempotencyConflict> { StagedJobUpload(root).publish(key) { it.write(byteArrayOf(1)); "original.elf" } }
        assertEquals(listOf(first.job.id), names(root))
    }

    @Test fun `concurrent identical keys publish one atomic job and one replay`() = withRoot { root ->
        val publisher = StagedJobUpload(root)
        val barrier = java.util.concurrent.CyclicBarrier(2)
        val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val results = (1..2).map { pool.submit<PublishedJobUpload> {
                publisher.publish("fixture_concurrent_key") { it.write(elfFixture()); barrier.await(5, java.util.concurrent.TimeUnit.SECONDS); "same.elf" }
            } }.map { it.get(5, java.util.concurrent.TimeUnit.SECONDS) }
            assertEquals(1, results.map { it.job.id }.toSet().size)
            assertEquals(1, results.count { it.replayed })
            assertEquals(listOf(results.first().job.id), names(root))
        } finally { pool.shutdownNow() }
    }

    @Test fun `post-rename retry recovers receipt and corruption cannot recreate the job`() = withRoot { root ->
        val key = "fixture_uncertain_key"
        val failed = assertFailsWith<UploadPublicationUncertain> {
            StagedJobUpload(root) { if (it == UploadPublishPoint.AFTER_RENAME) throw IOException("inert fault") }
                .publish(key) { it.write(elfFixture()); "saved.elf" }
        }
        val replay = StagedJobUpload(root).publish(key) { it.write(elfFixture()); "saved.elf" }
        assertEquals(failed.jobId, replay.job.id); assertTrue(replay.replayed)
        Files.writeString(root.resolve(failed.jobId).resolve("upload-receipt.json"), "corrupt fixture")
        assertFailsWith<UploadReceiptUnavailable> { StagedJobUpload(root).publish(key) { it.write(elfFixture()); "saved.elf" } }
        assertEquals(listOf(failed.jobId), names(root))
    }

    private fun names(root: java.nio.file.Path) = Files.list(root).use { entries -> entries.map { it.fileName.toString() }.sorted().toList() }
    private fun withRoot(block: (java.nio.file.Path) -> Unit) {
        val root = createTempDirectory("staged-upload-")
        try { block(root) } finally { root.toFile().deleteRecursively() }
    }
}
