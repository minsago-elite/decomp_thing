package decompengine.jobs

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JobStoreTest {
    @Test
    fun `caller mutation after parsing cannot change the published input`() {
        val root = createTempDirectory("jobs-owned-input-")
        val callerBytes = elfFixture()
        val expected = callerBytes.copyOf()
        val publisher = object : UploadPublisher by AtomicUploadPublisher {
            override fun writeAndForceInput(input: java.nio.file.Path, bytes: ByteArray) {
                callerBytes.fill(0)
                AtomicUploadPublisher.writeAndForceInput(input, bytes)
            }
        }
        val job = JobStore(root, publisher).createFromUpload("snapshot.elf", callerBytes)
        assertTrue(callerBytes.all { it == 0.toByte() })
        kotlin.test.assertContentEquals(expected, job.binaryPath.readBytes())
        assertEquals(decompengine.binary.ElfMetadataReader.read(expected), JobStore(root).get(job.id).metadata)
        assertEquals(expected.size, job.sizeBytes)
    }

    @Test
    fun `oversized input is rejected before storage is created`() {
        val root = createTempDirectory("jobs-input-limit-").resolve("uncreated-store")
        val failure = assertFailsWith<IllegalArgumentException> {
            JobStore(root).createFromUpload("too-large.elf", ByteArray(32 * 1024 * 1024 + 1))
        }
        assertEquals("upload exceeds the 32 MiB input limit", failure.message)
        assertTrue(!root.exists())
    }

    @Test
    fun `publication failures preserve a reviewable job identity without claiming rollback`() {
        for (phase in listOf("before-rename", "after-rename", "directory-force")) {
            val root = createTempDirectory("jobs-uncertain-$phase-")
            val privateError = "private storage diagnostic"
            val publisher = object : UploadPublisher {
                override fun writeAndForceInput(input: java.nio.file.Path, bytes: ByteArray) =
                    AtomicUploadPublisher.writeAndForceInput(input, bytes)

                override fun publish(staging: java.nio.file.Path, destination: java.nio.file.Path) {
                    if (phase == "before-rename") throw java.io.IOException(privateError)
                    AtomicUploadPublisher.publish(staging, destination)
                    if (phase == "after-rename") throw java.io.IOException(privateError)
                }

                override fun confirmDirectory(root: java.nio.file.Path) {
                    throw java.io.IOException(privateError)
                }
            }
            val failure = assertFailsWith<UploadPublicationUncertainException> {
                JobStore(root, publisher).createFromUpload("fixture.elf", elfFixture())
            }
            assertTrue(failure.jobId.matches(Regex("[a-f0-9]{32}")))
            assertTrue(!failure.message.orEmpty().contains(privateError))
            if (phase == "before-rename") {
                assertTrue(JobStore(root).list().isEmpty())
            } else {
                val published = JobStore(root).get(failure.jobId)
                assertEquals("uploaded", published.status)
                kotlin.test.assertContentEquals(elfFixture(), published.binaryPath.readBytes())
            }
            java.nio.file.Files.list(root).use { entries ->
                assertTrue(entries.noneMatch { it.fileName.toString().startsWith(".upload-") })
            }
            val problem = decompengine.web.uploadPublicationProblem(failure.jobId)
            assertEquals("\"upload_publication_uncertain\"", problem["error"].toString())
            assertEquals("false", problem["retry_upload"].toString())
            assertEquals("\"/jobs/${failure.jobId}\"", problem["job_url"].toString())
            val page = decompengine.web.renderUploadPublicationUncertainPage(failure.jobId)
            assertTrue(page.contains("href=\"/jobs/${failure.jobId}\""))
            assertTrue(page.contains("Check job"))
            assertTrue(!page.contains(privateError))
        }
    }

    @Test
    fun `metadata byte limit rejects unroundtrippable uploads and preserves readable jobs`() {
        val root = createTempDirectory("jobs-metadata-limit-")
        val store = JobStore(root)
        val acceptedName = "界".repeat(80_000)
        val accepted = store.createFromUpload(acceptedName, elfFixture())
        assertEquals(acceptedName, JobStore(root).get(accepted.id).filename)
        for (oversizedName in listOf("界".repeat(90_000), "\"".repeat(140_000), "a".repeat(300_000))) {
            val failure = assertFailsWith<InvalidUploadException> {
                store.createFromUpload(oversizedName, elfFixture())
            }
            assertTrue(failure.message.orEmpty().startsWith("job metadata exceeds the 256 KiB limit"))
            assertEquals(listOf(accepted.id), JobStore(root).list().map { it.id })
            java.nio.file.Files.list(root).use { entries ->
                assertEquals(listOf(accepted.id), entries.map { it.fileName.toString() }.toList())
            }
        }
        assertEquals("analyzing", store.updateStatus(accepted.id, "analyzing", "still readable").status)
        assertEquals("still readable", JobStore(root).get(accepted.id).statusMessage)
    }

    @Test
    fun `uploads reserve metadata space for later status updates`() {
        val root = createTempDirectory("jobs-status-headroom-")
        val store = JobStore(root)
        val limit = 256 * 1024
        val probe = store.createFromUpload("a".repeat(1_000), elfFixture())
        val fixedBytes = root.resolve(probe.id).resolve("job.json").toFile().length().toInt() - 1_000

        val rejected = "a".repeat(limit - fixedBytes - 1_500)
        val failure = assertFailsWith<InvalidUploadException> {
            store.createFromUpload(rejected, elfFixture())
        }
        assertEquals("job metadata exceeds the 256 KiB limit once later status updates are reserved", failure.message)
        assertEquals(listOf(probe.id), JobStore(root).list().map { it.id })

        val accepted = store.createFromUpload("a".repeat(limit - fixedBytes - 5_000), elfFixture())
        val message = "\u0001".repeat(500)
        assertEquals("queued", store.updateStatus(accepted.id, "queued", message).status)
        assertEquals(message, JobStore(root).get(accepted.id).statusMessage)
    }

    @Test
    fun `interrupted upload leaves no discoverable partial job or staging directory`() {
        val root = createTempDirectory("jobs-interrupted-upload-")
        val store = JobStore(root)
        val existing = store.createFromUpload("existing.elf", elfFixture())
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val worker = Thread {
            Thread.currentThread().interrupt()
            try {
                store.createFromUpload("interrupted.elf", elfFixture())
            } catch (problem: Throwable) {
                failure.set(problem)
            }
        }
        worker.start()
        worker.join(5000)
        assertTrue(!worker.isAlive)
        assertTrue(failure.get() is java.nio.channels.ClosedByInterruptException, failure.get().toString())
        assertEquals(listOf(existing.id), JobStore(root).list().map { it.id })
        java.nio.file.Files.list(root).use { entries ->
            assertEquals(listOf(existing.id), entries.map { it.fileName.toString() }.toList())
        }
        assertEquals(existing, store.get(existing.id))
    }

    @Test
    fun `metadata publication preserves the complete snapshot held by an existing reader`() {
        val root = createTempDirectory("jobs-atomic-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val metadata = root.resolve(job.id).resolve("job.json")
        val previous = metadata.readBytes()
        java.nio.channels.FileChannel.open(metadata).use { reader ->
            store.updateStatus(job.id, "analyzing", "replacement status")
            val buffer = java.nio.ByteBuffer.allocate(previous.size + 1024)
            while (reader.read(buffer) > 0) { }
            kotlin.test.assertContentEquals(previous, buffer.array().copyOf(buffer.position()))
        }
        assertEquals("analyzing", JobStore(root).get(job.id).status)
        java.nio.file.Files.list(root.resolve(job.id)).use { entries ->
            assertTrue(entries.noneMatch { it.fileName.toString().startsWith(".job-metadata-") })
        }
    }

    @Test
    fun `interrupted metadata update preserves the previous readable record`() {
        val root = createTempDirectory("jobs-interrupted-write-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val metadata = root.resolve(job.id).resolve("job.json")
        val previous = metadata.readBytes()
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val worker = Thread {
            Thread.currentThread().interrupt()
            try {
                store.updateStatus(job.id, "analyzing", "must not be published")
            } catch (problem: Throwable) {
                failure.set(problem)
            }
        }
        worker.start()
        worker.join(5000)
        assertTrue(!worker.isAlive)
        assertTrue(failure.get() is java.nio.channels.ClosedByInterruptException, failure.get().toString())
        kotlin.test.assertContentEquals(previous, metadata.readBytes())
        assertEquals("uploaded", JobStore(root).get(job.id).status)
        java.nio.file.Files.list(root.resolve(job.id)).use { entries ->
            assertTrue(entries.noneMatch { it.fileName.toString().startsWith(".job-metadata-") })
        }
    }

    @Test
    fun `backend stores uploaded ELF job and metadata`() {
        val tempDir = createTempDirectory("jobs-")
        val store = JobStore(tempDir)

        val job = store.createFromUpload("../fixture.elf", elfFixture())

        val jobDir = tempDir.resolve(job.id)
        assertEquals("fixture.elf", job.filename)
        assertEquals("uploaded", job.status)
        assertEquals(elfFixture().size, job.sizeBytes)
        assertEquals(jobDir.resolve("input.elf"), job.binaryPath)
        assertEquals("x86-64", job.metadata.machine)
        assertEquals(0x401000UL, job.metadata.entryPoint)
        assertTrue(job.binaryPath.readBytes().contentEquals(elfFixture()))

        val metadata = Json.parseToJsonElement(jobDir.resolve("job.json").readText()).jsonObject
        assertEquals(job.id, metadata["id"].toString().trim('"'))
        assertEquals("ELF64", metadata["metadata"]!!.jsonObject["format"].toString().trim('"'))

        assertEquals(job, store.get(job.id))
        // Older releases used the general serializer's pretty-printed field ordering.
        jobDir.resolve("job.json").writeText(Json { prettyPrint = true }.encodeToString(
            kotlinx.serialization.json.JsonElement.serializer(), job.toJson()))
        assertEquals(job, JobStore(tempDir).get(job.id))
    }

    @Test
    fun `backend rejects non-ELF upload`() {
        val store = JobStore(createTempDirectory("jobs-invalid-"))

        assertFailsWith<InvalidUploadException> {
            store.createFromUpload("not-elf.bin", "not an elf".toByteArray())
        }
    }

    @Test
    fun `backend lists jobs and persists analysis status`() {
        val store = JobStore(createTempDirectory("jobs-status-"))
        val first = store.createFromUpload("first.elf", elfFixture())
        val second = store.createFromUpload("second.elf", elfFixture())

        val updated = store.updateStatus(first.id, "analyzing", "Exploring candidate inputs")

        assertEquals("analyzing", updated.status)
        assertEquals("Exploring candidate inputs", updated.statusMessage)
        assertEquals("analyzing", store.get(first.id).status)
        assertEquals(setOf(second.id, first.id), store.list().map { it.id }.toSet())
    }

    @Test
    fun `backend resolves only job-local artifact files`() {
        val root = createTempDirectory("jobs-artifacts-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val report = store.reportsDirectory(job.id).resolve("exploration.json")
        report.writeText("{}")

        assertEquals(report, store.resolveArtifact(job.id, "reports/exploration.json"))
        assertFailsWith<IllegalArgumentException> { store.resolveArtifact(job.id, "../job.json") }
        assertFailsWith<IllegalArgumentException> { store.resolveArtifact(job.id, "job.json") }
        assertFailsWith<JobStoreException> { store.resolveArtifact(job.id, "reports/missing.json") }
    }

    @Test
    fun `backend marks interrupted analysis jobs failed on recovery`() {
        val store = JobStore(createTempDirectory("jobs-recovery-"))
        val job = store.createFromUpload("fixture.elf", elfFixture())
        store.updateStatus(job.id, "analyzing", "running")

        store.recoverInterruptedJobs()

        val recovered = store.get(job.id)
        assertEquals("failed", recovered.status)
        assertTrue(recovered.statusMessage.orEmpty().contains("interrupted"))
    }
}

fun elfFixture(): ByteArray {
    val bytes = ByteArray(64)
    bytes[0] = 0x7f
    bytes[1] = 'E'.code.toByte()
    bytes[2] = 'L'.code.toByte()
    bytes[3] = 'F'.code.toByte()
    bytes[4] = 2
    bytes[5] = 1
    bytes[6] = 1
    bytes[7] = 3
    putShort(bytes, 16, 2)
    putShort(bytes, 18, 62)
    putInt(bytes, 20, 1)
    putLong(bytes, 24, 0x401000)
    putLong(bytes, 32, 64)
    putLong(bytes, 40, 0)
    putInt(bytes, 48, 0)
    putShort(bytes, 52, 64)
    putShort(bytes, 54, 56)
    putShort(bytes, 56, 2)
    putShort(bytes, 58, 64)
    putShort(bytes, 60, 5)
    putShort(bytes, 62, 4)
    return bytes
}

private fun putShort(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = value.toByte()
    bytes[offset + 1] = (value ushr 8).toByte()
}

private fun putInt(bytes: ByteArray, offset: Int, value: Int) {
    repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}

private fun putLong(bytes: ByteArray, offset: Int, value: Long) {
    repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}
