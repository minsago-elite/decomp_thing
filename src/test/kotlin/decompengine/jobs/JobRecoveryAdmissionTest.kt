package decompengine.jobs

import kotlin.io.path.*
import kotlin.test.*
import kotlinx.serialization.json.*

class JobRecoveryAdmissionTest {
    @Test fun `entry exhaustion leaves all statuses unchanged and retry can recover`() {
        val root = createTempDirectory("recovery-entry-limit-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        root.resolve("retained-unknown-entry").writeText("private-content")
        val before = root.resolve(job.id).resolve("job.json").readBytes()
        assertIncomplete { store.recoverInterruptedJobs(1, 64L * 1024 * 1024) }
        assertContentEquals(before, root.resolve(job.id).resolve("job.json").readBytes())
        assertEquals("private-content", root.resolve("retained-unknown-entry").readText())
        store.recoverInterruptedJobs()
        assertEquals("failed", store.get(job.id).status)
    }

    @Test fun `aggregate metadata exhaustion precedes every recovery write`() {
        val root = createTempDirectory("recovery-byte-limit-")
        val store = JobStore(root)
        val jobs = List(2) { store.createFromUpload("fixture.elf", elfFixture()) }
        jobs.forEach { store.updateStatus(it.id, "queued") }
        val paths = jobs.map { root.resolve(it.id).resolve("job.json") }
        val before = paths.map { it.readBytes() }
        val budget = before.sumOf { it.size.toLong() } - 1
        assertIncomplete { store.recoverInterruptedJobs(4096, budget) }
        paths.forEachIndexed { index, path -> assertContentEquals(before[index], path.readBytes()) }
        store.recoverInterruptedJobs(4096, budget + 1)
        assertTrue(jobs.all { store.get(it.id).status == "failed" })
    }

    @Test fun `unreadable candidate prevents partial reconciliation and hides diagnostic content`() {
        val root = createTempDirectory("recovery-invalid-record-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing")
        val before = root.resolve(job.id).resolve("job.json").readBytes()
        val malformed = root.resolve("a".repeat(32)).createDirectory().resolve("job.json")
        malformed.writeText("private-token invalid JSON")
        assertIncomplete { store.recoverInterruptedJobs() }
        assertContentEquals(before, root.resolve(job.id).resolve("job.json").readBytes())
        assertEquals("private-token invalid JSON", malformed.readText())
    }

    @Test fun `cancellation before or during inspection leaves every record unchanged`() {
        for (cancelOnCall in listOf(1, 2)) {
            val root = createTempDirectory("recovery-cancel-scan-")
            val store = JobStore(root)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            store.updateStatus(job.id, "queued")
            val path = root.resolve(job.id).resolve("job.json")
            val before = path.readBytes()
            var calls = 0
            val failure = assertFailsWith<JobRecoveryCancelledException> {
                store.recoverInterruptedJobs { ++calls == cancelOnCall }
            }
            assertFalse(failure.statusUpdatesStarted)
            assertContentEquals(before, path.readBytes())
        }
    }

    @Test fun `cancellation between status writes retains completed reconciliation and leaves later jobs pending`() {
        val root = createTempDirectory("recovery-cancel-write-")
        val store = JobStore(root)
        val jobs = List(2) { store.createFromUpload("fixture.elf", elfFixture()) }
        jobs.forEach { store.updateStatus(it.id, "queued") }
        val failure = assertFailsWith<JobRecoveryCancelledException> {
            store.recoverInterruptedJobs { jobs.any { store.get(it.id).status == "failed" } }
        }
        assertTrue(failure.statusUpdatesStarted)
        assertEquals(listOf("failed", "queued"), jobs.map { store.get(it.id).status }.sorted())
        store.recoverInterruptedJobs()
        assertTrue(jobs.all { store.get(it.id).status == "failed" })
    }

<<<<<<< HEAD
    @Test fun `cancellation during the final publication is reported without clearing interruption`() {
        for (interrupt in listOf(false, true)) {
            val root = createTempDirectory("recovery-final-cancellation-")
            var armed = false
            var cancelled = false
            val publisher = object : JobMetadataPublisher by AtomicJobMetadataPublisher {
                override fun confirmDirectory(directory: java.nio.file.Path) {
                    AtomicJobMetadataPublisher.confirmDirectory(directory)
                    if (armed) {
                        if (interrupt) Thread.currentThread().interrupt() else cancelled = true
                    }
                }
            }
            val store = JobStore(root, AtomicUploadPublisher, publisher)
            val job = store.createFromUpload("fixture.elf", elfFixture())
            store.updateStatus(job.id, "queued")
            armed = true
            try {
                val failure = assertFailsWith<JobRecoveryCancelledException> {
                    store.recoverInterruptedJobs { cancelled }
                }
                assertTrue(failure.statusUpdatesStarted)
                assertEquals(interrupt, Thread.currentThread().isInterrupted)
            } finally {
                if (interrupt) Thread.interrupted()
                armed = false
            }
            try { assertEquals("failed", store.get(job.id).status) }
            finally { root.toFile().deleteRecursively() }
        }
=======
    @Test fun `unsupported schema and lossy numeric coercions cannot pass recovery inspection`() {
        val root = createTempDirectory("recovery-schema-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "queued")
        val path = root.resolve(job.id).resolve("job.json")
        val original = path.readBytes()
        val record = Json.parseToJsonElement(original.decodeToString()).jsonObject
        val elf = record.getValue("metadata").jsonObject
        val invalid = listOf(
            record + ("future_field" to JsonPrimitive("private-value")),
            record + ("filename" to JsonPrimitive(123)),
            record + ("size_bytes" to JsonPrimitive(-1)),
            record + ("size_bytes" to JsonPrimitive(32L * 1024 * 1024 + 1)),
            record + ("size_bytes" to JsonPrimitive("64")),
            record + ("metadata" to JsonObject(elf + ("elf_header_size" to JsonPrimitive(65536)))),
            record + ("metadata" to JsonObject(elf + ("elf_version" to JsonPrimitive(-1)))),
            record + ("metadata" to JsonObject(elf + ("future_field" to JsonPrimitive("private-value")))),
        )
        invalid.forEach { fields ->
            path.writeText(JsonObject(fields).toString())
            val before = path.readBytes()
            assertFailsWith<IllegalArgumentException> { store.get(job.id) }
            assertIncomplete { store.recoverInterruptedJobs() }
            assertContentEquals(before, path.readBytes())
        }
        // Older records may omit updated_at and carry a null optional status message.
        path.writeText(JsonObject(record - "updated_at" + ("status_message" to JsonNull)).toString())
        assertEquals(job.createdAt, store.get(job.id).updatedAt)
        assertNull(store.get(job.id).statusMessage)
        store.recoverInterruptedJobs()
        assertEquals("failed", store.get(job.id).status)
>>>>>>> be07aceb (Reject lossy or unsupported job metadata before recovery [skip ci])
    }

    private fun assertIncomplete(action: () -> Unit) {
        val failure = assertFailsWith<JobStoreException>(block = action)
        assertEquals("Job recovery inspection is incomplete; no recovery statuses were changed", failure.message)
        assertNull(failure.cause)
    }
}
