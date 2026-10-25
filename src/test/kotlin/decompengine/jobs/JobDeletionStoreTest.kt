package decompengine.jobs

import java.nio.file.Files
import kotlin.io.path.writeBytes
import kotlin.test.*

class JobDeletionStoreTest {
    private val digest = "0".repeat(64)

    @Test fun `a foreign-owned descendant stops cleanup and the detached job keeps its tombstone`() {
        val root = Files.createTempDirectory("job-deletion-store-")
        try {
            val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
            val nested = Files.createDirectories(root.resolve("${job.id}/reports/runs/run_a"))
            nested.resolve("foreign.bin").writeBytes(byteArrayOf(9, 9))
            // Production compares UIDs; the fixture marks one entry foreign because tests cannot chown.
            val store = JobDeletionStore(root, owned = { name, entry, owner -> name != "foreign.bin" && entry.uid == owner.uid })
            store.load()
            val running = store.detach(store.admit(job.id, digest, "1".repeat(64), "2".repeat(64)))
            val result = store.purge(running, { true })
            assertFalse(result.complete); assertEquals("CLEANUP_CONTAINMENT", result.failureCode)
            val failed = store.record(running, result)
            assertEquals(JobDeletionState.FAILED, failed.state); assertEquals("CLEANUP_CONTAINMENT", failed.failureCode)
            val preserved = root.resolve("${JobDeletionStore.DIRECTORY}/${running.operationId}.removing/reports/runs/run_a/foreign.bin")
            assertContentEquals(byteArrayOf(9, 9), Files.readAllBytes(preserved), "the foreign entry is neither traversed nor unlinked")
            assertFalse(Files.exists(root.resolve(job.id)))
            assertEquals(failed.operationId, store.deleted(job.id)?.operationId, "a containment stop happens after detachment")
            val reopened = JobDeletionStore(root).also { it.load() }
            assertEquals(failed.operationId, reopened.deleted(job.id)?.operationId, "the tombstone survives restart")
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun `a deletion that failed before detachment is not a tombstone`() {
        val root = Files.createTempDirectory("job-deletion-store-")
        try {
            val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
            val store = JobDeletionStore(root, faults = JobDeletionFaults { point ->
                if (point == JobDeletionFaultPoint.BEFORE_DETACH) throw java.io.IOException("read-only")
            })
            store.load()
            val admitted = store.admit(job.id, digest, "1".repeat(64), "2".repeat(64))
            assertFailsWith<JobStorageWriteException> { store.detach(admitted) }
            assertNull(store.deleted(job.id))
            assertTrue(Files.isDirectory(root.resolve(job.id)))
        } finally { root.toFile().deleteRecursively() }
    }
}
