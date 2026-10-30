package decompengine.jobs

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import decompengine.repair.open
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class JobStoreTest {
    @Test
    fun `strict metadata read detects only owned sibling directory link count change`() {
        val root = createTempDirectory("jobs-metadata-sibling-diagnostic-")
        val store = JobStore(root)
        val job = store.createFromUpload("snapshot.elf", elfFixture())
        val jobDirectory = root.resolve(job.id)
        val metadata = jobDirectory.resolve("job.json")
        val beforeDirectory = directoryIdentity(jobDirectory)
        val beforeMetadata = fileIdentity(metadata)
        val beforeBytes = java.nio.file.Files.readAllBytes(metadata)
        var afterDirectory: decompengine.acp.LinuxFileIdentity? = null
        var afterMetadata: decompengine.acp.LinuxFileIdentity? = null
        var afterBytes: ByteArray? = null

        val read = runCatching {
            decompengine.repair.readStableRegularFile(root, "${job.id}/job.json", 256 * 1024L,
                afterAuthorization = {
                    store.reportsDirectory(job.id)
                    assertTrue(java.nio.file.Files.isDirectory(jobDirectory.resolve("reports")))
                    afterDirectory = directoryIdentity(jobDirectory)
                    afterMetadata = fileIdentity(metadata)
                    afterBytes = java.nio.file.Files.readAllBytes(metadata)
                })
        }

        val observedDirectory = checkNotNull(afterDirectory) { "authorization callback did not run" }
        assertEquals(beforeDirectory.copy(linkCount = observedDirectory.linkCount), observedDirectory)
        assertEquals(beforeMetadata, afterMetadata)
        kotlin.test.assertContentEquals(beforeBytes, afterBytes)
        val linkCountChanged = beforeDirectory.linkCount != observedDirectory.linkCount
        assumeTrue(linkCountChanged,
            "filesystem ${java.nio.file.Files.getFileStore(root).type()} did not change directory nlink for owned sibling creation")

        val refusal = read.exceptionOrNull()
        assertTrue(refusal is IllegalArgumentException)
        assertEquals("stable file-read directory binding changed", refusal.message)
        assertTrue(store.get(job.id).binaryPath.toFile().isFile)
    }

    private fun directoryIdentity(path: java.nio.file.Path): decompengine.acp.LinuxFileIdentity =
        decompengine.acp.LinuxFilesystemSyscalls.openAbsolutePathOrNull(path).use { descriptor ->
            decompengine.acp.LinuxFilesystemSyscalls.identity(requireNotNull(descriptor).fd)
        }

    private fun fileIdentity(path: java.nio.file.Path): decompengine.acp.LinuxFileIdentity = directoryIdentity(path)

    @Test
    fun `job metadata read accepts owned sibling directory creation and removal`() {
        fun exercise(
            label: String,
            beforeRead: (java.nio.file.Path) -> Unit = {},
            duringRead: (java.nio.file.Path) -> Unit,
        ): Boolean {
            val root = createTempDirectory("jobs-metadata-$label-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val jobDirectory = root.resolve(job.id)
            val metadata = jobDirectory.resolve("job.json")
            beforeRead(jobDirectory)
            val beforeDirectory = directoryIdentity(jobDirectory)
            val beforeMetadata = fileIdentity(metadata)
            val beforeBytes = java.nio.file.Files.readAllBytes(metadata)
            var afterDirectory: decompengine.acp.LinuxFileIdentity? = null
            var afterMetadata: decompengine.acp.LinuxFileIdentity? = null
            var afterBytes: ByteArray? = null

            val result = store.getWithMetadataAuthorization(job.id) {
                duringRead(jobDirectory)
                afterDirectory = directoryIdentity(jobDirectory)
                afterMetadata = fileIdentity(metadata)
                afterBytes = java.nio.file.Files.readAllBytes(metadata)
            }

            val observedDirectory = checkNotNull(afterDirectory)
            assertEquals(beforeDirectory.copy(linkCount = observedDirectory.linkCount), observedDirectory)
            assertEquals(beforeMetadata, afterMetadata)
            kotlin.test.assertContentEquals(beforeBytes, afterBytes)
            assertEquals(job, result)
            return beforeDirectory.linkCount != observedDirectory.linkCount
        }

        val creationChangedLinkCount = exercise("sibling-create") { directory ->
            java.nio.file.Files.createDirectory(directory.resolve("reports"))
        }
        val removalChangedLinkCount = exercise(
            "sibling-remove",
            beforeRead = { directory -> java.nio.file.Files.createDirectory(directory.resolve("reports")) },
            duringRead = { directory -> java.nio.file.Files.delete(directory.resolve("reports")) },
        )
        val filesystemType = java.nio.file.Files.getFileStore(java.nio.file.Path.of(".")).type()
        assumeTrue(creationChangedLinkCount && removalChangedLinkCount,
            "filesystem $filesystemType did not change directory nlink for both owned sibling controls")
    }

    @Test
    fun `job metadata read still refuses directory and target replacement`() {
        run {
            val root = createTempDirectory("jobs-metadata-parent-replacement-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val jobDirectory = root.resolve(job.id)
            val failure = assertFailsWith<IllegalArgumentException> {
                store.getWithMetadataAuthorization(job.id) {
                    val retained = root.resolve("retained-job-directory")
                    java.nio.file.Files.move(jobDirectory, retained)
                    java.nio.file.Files.createDirectory(jobDirectory)
                    java.nio.file.Files.copy(retained.resolve("job.json"), jobDirectory.resolve("job.json"))
                }
            }
            assertTrue(
                failure.message in setOf(
                    "stable file-read directory binding changed",
                    "stable file-read root binding changed",
                ),
                "directory replacement must be refused by a pinned path binding check",
            )
        }

        run {
            val root = createTempDirectory("jobs-metadata-target-replacement-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val metadata = root.resolve(job.id).resolve("job.json")
            val failure = assertFailsWith<IllegalArgumentException> {
                store.getWithMetadataAuthorization(job.id) {
                    val retained = metadata.resolveSibling("retained-job.json")
                    java.nio.file.Files.move(metadata, retained)
                    java.nio.file.Files.copy(retained, metadata)
                }
            }
            assertEquals("stable file-read target binding changed", failure.message)
        }

        run {
            val root = createTempDirectory("jobs-metadata-root-replacement-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val failure = assertFailsWith<IllegalArgumentException> {
                store.getWithMetadataAuthorization(job.id) {
                    val retainedRoot = root.resolveSibling("${root.fileName}-retained")
                    java.nio.file.Files.move(root, retainedRoot)
                    java.nio.file.Files.createDirectory(root)
                    val replacementJob = java.nio.file.Files.createDirectory(root.resolve(job.id))
                    java.nio.file.Files.copy(retainedRoot.resolve(job.id).resolve("job.json"), replacementJob.resolve("job.json"))
                }
            }
            assertEquals("stable file-read root binding changed", failure.message)
        }

        run {
            val root = createTempDirectory("jobs-metadata-hardlink-replacement-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val metadata = root.resolve(job.id).resolve("job.json")
            val failure = assertFailsWith<IllegalArgumentException> {
                store.getWithMetadataAuthorization(job.id) {
                    java.nio.file.Files.createLink(metadata.resolveSibling("retained-job.json"), metadata)
                }
            }
            assertTrue(failure.message.orEmpty().contains("descriptor identity differs"))
        }

        run {
            val root = createTempDirectory("jobs-metadata-symlink-replacement-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val metadata = root.resolve(job.id).resolve("job.json")
            val failure = assertFailsWith<IllegalArgumentException> {
                store.getWithMetadataAuthorization(job.id) {
                    val retained = metadata.resolveSibling("retained-job.json")
                    java.nio.file.Files.move(metadata, retained)
                    java.nio.file.Files.createSymbolicLink(metadata, retained.fileName)
                }
            }
            assertEquals("stable file-read target binding changed", failure.message)
        }

        run {
            val root = createTempDirectory("jobs-metadata-mode-change-")
            val store = JobStore(root)
            val job = store.createFromUpload("snapshot.elf", elfFixture())
            val metadata = root.resolve(job.id).resolve("job.json")
            val originalMode = java.nio.file.Files.getPosixFilePermissions(metadata)
            val failure = try {
                assertFailsWith<IllegalArgumentException> {
                    store.getWithMetadataAuthorization(job.id) {
                        java.nio.file.Files.setPosixFilePermissions(
                            metadata,
                            originalMode - java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                        )
                    }
                }
            } finally {
                java.nio.file.Files.setPosixFilePermissions(metadata, originalMode)
            }
            assertTrue(failure.message.orEmpty().contains("identity differs"))
        }
    }

    @Test
    fun `artifact reads enforce the selected byte bound and reject retained file or directory substitution`() {
        val root = createTempDirectory("jobs-artifact-snapshot-")
        val store = JobStore(root)
        val job = store.createFromUpload("snapshot.elf", elfFixture())
        val reports = java.nio.file.Files.createDirectory(root.resolve(job.id).resolve("reports"))
        val path = reports.resolve("ordinary.json")
        val payload = "{\"observation\":\"bounded\"}".toByteArray()
        java.nio.file.Files.write(path, payload)
        val selected = store.readArtifact(job.id, "reports/ordinary.json", payload.size.toLong())
        kotlin.test.assertContentEquals(payload, selected.bytes)
        assertEquals(decompengine.project.sha256(payload), selected.sha256)
        assertFailsWith<decompengine.repair.RepairBudgetExceededException> {
            store.readArtifact(job.id, "reports/ordinary.json", payload.size.toLong() - 1)
        }
        val moved = reports.resolve("retained.json")
        val replacedFile = assertFailsWith<IllegalArgumentException> {
            decompengine.repair.readStableRegularFile(root, "${job.id}/reports/ordinary.json", payload.size.toLong(),
                afterAuthorization = {
                    java.nio.file.Files.move(path, moved)
                    java.nio.file.Files.write(path, payload)
                })
        }
        assertTrue(replacedFile.message.orEmpty().contains("target binding changed"))
        java.nio.file.Files.delete(path)
        java.nio.file.Files.move(moved, path)
        val replacementReports = java.nio.file.Files.createDirectory(reports.resolveSibling("replacement-reports"))
        java.nio.file.Files.write(replacementReports.resolve("ordinary.json"), payload)
        val replacedDirectory = assertFailsWith<IllegalArgumentException> {
            decompengine.repair.readStableRegularFile(root, "${job.id}/reports/ordinary.json", payload.size.toLong(),
                afterRead = {
                    java.nio.file.Files.move(reports, reports.resolveSibling("retained-reports"))
                    java.nio.file.Files.move(replacementReports, reports)
                })
        }
        assertTrue(replacedDirectory.message.orEmpty().contains("directory binding changed"))
        kotlin.test.assertContentEquals(payload, store.readArtifact(job.id, "reports/ordinary.json", payload.size.toLong()).bytes)
    }

    @Test
    fun `upload admission reserves room for every supported status message`() {
        val root = createTempDirectory("jobs-status-reserve-")
        val store = JobStore(root)
        // This filename fits the initial record but not its largest later status update.
        assertFailsWith<InvalidUploadException> {
            store.createFromUpload("a".repeat(256 * 1024 - 1100), elfFixture())
        }
        assertTrue(store.list().isEmpty())
        java.nio.file.Files.list(root).use { assertEquals(0, it.count()) }
        val job = store.createFromUpload("a".repeat(256 * 1024 - 4000), elfFixture())
        for (message in listOf("\u0001".repeat(500), "界".repeat(500), "\"".repeat(500))) {
            for (status in listOf("queued", "analyzing", "complete", "failed", "uploaded")) {
                store.updateStatus(job.id, status, message)
                val read = JobStore(root).get(job.id)
                assertEquals(status, read.status)
                assertEquals(message, read.statusMessage)
            }
        }
    }

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
    @Test
    fun `recorded history selects only the exact legacy or named run layout`() {
        val root = historyTestRoot()
        val id = "a".repeat(32)
        val legacy = historyProject(root.resolve("$id/reports/source-tree"))
        val run = historyProject(root.resolve("$id/reports/runs/selected-run/source-tree"), "run-base")
        val store = JobStore(root)
        val legacyResult = store.readRecordedRepairHistory(id, null)
        val runResult = store.readRecordedRepairHistory(id, "selected-run")
        assertEquals(decompengine.repair.RepairHistoryReadStatus.RECORDED, legacyResult.status)
        assertEquals(decompengine.repair.RepairHistoryReadStatus.RECORDED, runResult.status)
        assertEquals(decompengine.project.sha256(legacy.resolve("reports/repair-revisions/graph.json").readBytes()), legacyResult.snapshot?.graphSha256)
        assertEquals(decompengine.project.sha256(run.resolve("reports/repair-revisions/graph.json").readBytes()), runResult.snapshot?.graphSha256)
        assertTrue(legacyResult.snapshot?.graphSha256 != runResult.snapshot?.graphSha256)
        assertEquals(decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED, store.readRecordedRepairHistory(id, "missing-run").status)
        assertEquals(decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED, store.readRecordedRepairHistory("b".repeat(32), null).status)
        for (bad in listOf("../selected-run", "", "a/b", "a".repeat(129))) {
            val refused = store.readRecordedRepairHistory(id, bad)
            assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, refused.status)
            kotlin.test.assertNull(refused.snapshot)
        }
        assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, store.readRecordedRepairHistory("../outside", null).status)
    }

    @Test
    fun `recorded history absence is read only and never constructs store or recovery`() {
        val root = historyTestRoot()
        val absent = root.resolve("absent-store")
        val missingRoot = JobStore(absent).readRecordedRepairHistory("a".repeat(32), null)
        assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, missingRoot.status)
        assertTrue(!java.nio.file.Files.exists(absent))
        val selected = root.resolve("a".repeat(32))
        java.nio.file.Files.createDirectory(selected)
        val store = JobStore(root)
        val missingHistory = store.readRecordedRepairHistory("a".repeat(32), null)
        assertEquals(decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED, missingHistory.status)
        java.nio.file.Files.list(selected).use { assertEquals(0L, it.count()) }
    }

    @Test
    fun `recorded history rejects selected symlink and cancellation without fallback or private failures`() {
        val root = historyTestRoot()
        val id = "a".repeat(32)
        val legacy = historyProject(root.resolve("$id/reports/source-tree"))
        val before = legacy.resolve("reports/repair-revisions/graph.json").readBytes()
        val runs = root.resolve("$id/reports/runs")
        java.nio.file.Files.createDirectory(runs)
        java.nio.file.Files.createSymbolicLink(runs.resolve("selected-run"), root.resolve("$id/reports"))
        val store = JobStore(root)
        val link = store.readRecordedRepairHistory(id, "selected-run")
        assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, link.status)
        kotlin.test.assertNull(link.snapshot)
        val cancelled = store.readRecordedRepairHistory(id, null) { throw IllegalStateException("PRIVATE-job-path-token") }
        assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, cancelled.status)
        kotlin.test.assertNull(cancelled.snapshot)
        kotlin.test.assertContentEquals(before, legacy.resolve("reports/repair-revisions/graph.json").readBytes())
        assertEquals(decompengine.repair.RepairHistoryReadStatus.RECORDED, store.readRecordedRepairHistory(id, null).status)
    }


    @Test
    fun `recorded projection uses only selected source tree reports without outer fallback`() {
        val root = historyTestRoot()
        val id = "a".repeat(32)
        val legacy = historyProject(root.resolve("$id/reports/source-tree"))
        val run = historyProject(root.resolve("$id/reports/runs/selected-run/source-tree"), "run-base")
        val store = JobStore(root)
        val outer = root.resolve("$id/reports/repair_history.json")
        outer.writeText("PRIVATE-outer-history-must-not-be-selected")
        val legacyH = legacy.resolve("reports/repair_history.json")
        val runH = run.resolve("reports/repair_history.json")
        java.nio.file.Files.deleteIfExists(legacyH)
        java.nio.file.Files.deleteIfExists(runH)
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.MISSING,
            store.readRecordedRepairHistory(id, null).projection.status)
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.MISSING,
            store.readRecordedRepairHistory(id, "selected-run").projection.status)
        runH.writeText("")
        legacyH.writeText("PRIVATE-corrupt-legacy-only")
        val selected = store.readRecordedRepairHistory(id, "selected-run")
        assertEquals(decompengine.repair.RepairHistoryReadStatus.RECORDED, selected.status)
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.EMPTY, selected.projection.status)
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.INVALID,
            store.readRecordedRepairHistory(id, null).projection.status)
        val profile = decompengine.repair.DeclarativeRepairIndexProfile("job-history-reader",
            decompengine.repair.RepairIndexLayout(listOf("code.c"), listOf("code.c")))
        decompengine.repair.ModuleRevisionGraph.open(run, profile).use { it.synchronizeRepairHistory() }
        val beforeH = runH.readBytes()
        val beforeG = run.resolve("reports/repair-revisions/graph.json").readBytes()
        val beforeSource = run.resolve("code.c").readBytes()
        val matched = store.readRecordedRepairHistory(id, "selected-run")
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, matched.projection.status)
        assertEquals(decompengine.project.sha256(beforeH), matched.projection.capturedSha256)
        kotlin.test.assertContentEquals(beforeH, runH.readBytes())
        kotlin.test.assertContentEquals(beforeG, run.resolve("reports/repair-revisions/graph.json").readBytes())
        kotlin.test.assertContentEquals(beforeSource, run.resolve("code.c").readBytes())
        assertEquals("PRIVATE-outer-history-must-not-be-selected", outer.readText())
        assertEquals(decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED,
            store.readRecordedRepairHistory(id, "not-selected").status)
    }

    @Test
    fun `selected projection cannot turn cancellation or absent selected run into recorded credit`() {
        val root = historyTestRoot()
        val id = "a".repeat(32)
        val project = historyProject(root.resolve("$id/reports/source-tree"))
        project.resolve("reports/repair_history.json").writeText("PRIVATE-malformed")
        val store = JobStore(root)
        val cancelled = store.readRecordedRepairHistory(id, null) { throw IllegalStateException("PRIVATE-cancel") }
        assertEquals(decompengine.repair.RepairHistoryReadStatus.UNAVAILABLE, cancelled.status)
        kotlin.test.assertNull(cancelled.snapshot)
        assertEquals(decompengine.repair.RepairHistoryProjectionStatus.NOT_INSPECTED, cancelled.projection.status)
        val missing = root.resolve("$id/reports/runs/missing-run")
        assertEquals(decompengine.repair.RepairHistoryReadStatus.NOT_RECORDED,
            store.readRecordedRepairHistory(id, "missing-run").status)
        assertTrue(!java.nio.file.Files.exists(missing))
        assertEquals("base", project.resolve("code.c").readText())
    }

    private fun historyTestRoot(): java.nio.file.Path {
        val parent = java.nio.file.Path.of("build/test-tmp").toAbsolutePath().normalize()
        java.nio.file.Files.createDirectories(parent)
        return createTempDirectory(parent, "job-history-reader-")
    }

    private fun historyProject(root: java.nio.file.Path, source: String = "base"): java.nio.file.Path {
        java.nio.file.Files.createDirectories(root)
        root.resolve("code.c").writeText(source)
        val profile = decompengine.repair.DeclarativeRepairIndexProfile("job-history-reader",
            decompengine.repair.RepairIndexLayout(listOf("code.c"), listOf("code.c")))
        decompengine.repair.ModuleRevisionGraph.open(root, profile).use { it.enableRunContract() }
        return root
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
