package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.jobs.WorkflowStartupRecoveryBudget
import decompengine.jobs.WorkflowStartupRecoveryLimits
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.CancellationException
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import kotlinx.serialization.json.*
import org.junit.jupiter.api.extension.ExtendWith
import kotlin.io.path.*
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class ReconstructionOutputPublicationTest {
    @Test
    fun `abrupt process death during decided member swaps recovers the committed generation`() {
        val fixture = fixture("publication-abrupt-process-crash-")
        writeGeneration(fixture.root, "accepted")
        val process = ProcessBuilder(
            Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Djava.io.tmpdir=${System.getProperty("java.io.tmpdir")}",
            "-cp", System.getProperty("java.class.path"),
            ReconstructionOutputPublicationCrashFixture::class.java.name,
            fixture.root.toString(), fixture.input.toString(), "11",
        ).redirectErrorStream(true).redirectOutput(fixture.scratch.resolve("crash-child.log").toFile())
            .apply { environment().clear() }.start()
        try {
            assertTrue(process.waitFor(20, TimeUnit.SECONDS), "publication crash child did not halt")
            assertEquals(86, process.exitValue(), Files.readString(fixture.scratch.resolve("crash-child.log")))
            assertTrue(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
            assertEquals("{\"generation\":\"candidate\"}\n",
                readCommittedFileWithoutAtime(fixture.root, "reconstruction.json").decodeToString())
            assertFalse(fixture.root.resolve("source-tree/module.c").exists(),
                "the crash point must leave an incomplete live generation before recovery")

            ReconstructionOutputWorkspace.open(fixture.root, fixture.input).use { }

            assertEquals(generationHashes(fixture.root, "candidate"), captureGeneration(fixture.root))
            assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
            assertFalse(Files.newDirectoryStream(fixture.root).use { stream -> stream.any {
                it.fileName.toString().startsWith(".reconstruction-stage-") ||
                    it.fileName.toString().startsWith(".reconstruction-previous-")
            } })
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `every accepted member rolls back together on agent validator and cancellation refusal`() {
        val members = setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions")
        for (failureKind in listOf("agent", "validator", "cancellation")) {
            val fixture = fixture("publication-multi-rollback-")
            writeGeneration(fixture.root, "accepted")
            val before = captureGeneration(fixture.root)
            val beforeMetadata = captureGenerationMetadata(fixture.root)
            if (failureKind == "cancellation") {
                assertEquals(PublicationResult.REJECTED, publish(
                    fixture, members, { writeGeneration(it, "candidate") },
                    cancellationCheck = { throw CancellationException("cancel before the commit decision") },
                ))
            } else {
                assertFails {
                    publish(fixture, members, { stage ->
                        writeGeneration(stage, "candidate")
                        if (failureKind == "agent") throw IOException("agent failed before publication")
                        Files.createSymbolicLink(stage.resolve("source-tree/escape"), fixture.scratch)
                    })
                }
            }
            assertEquals(before, captureGeneration(fixture.root), "$failureKind must preserve all accepted members byte-for-byte")
            assertEquals(beforeMetadata, captureGenerationMetadata(fixture.root),
                "$failureKind must preserve committed file metadata and directory commitments")
            assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        }
    }

    @Test
    fun `committed publication journal remains until attempt reconciliation acknowledges it`() {
        val fixture = fixture("publication-attempt-ack-")
        writeGeneration(fixture.root, "accepted")
        val members = setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions")
        ReconstructionOutputWorkspace.open(fixture.root, fixture.input).use { workspace ->
            assertEquals(PublicationResult.PENDING, workspace.publish(members,
                { stage -> writeGeneration(stage, "candidate") },
                onCommitted = { throw IOException("attempt receipt could not be persisted") }))
        }
        val journal = fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION)
        assertTrue(journal.exists(), "failed attempt reconciliation must retain the committed journal")
        assertEquals(generationHashes(fixture.root, "candidate"), captureGeneration(fixture.root))

        assertFailsWith<IOException> {
            ReconstructionOutputWorkspace.openForStartupRecovery(
                fixture.root, fixture.input, WorkflowStartupRecoveryBudget(WorkflowStartupRecoveryLimits()),
            ) { throw IOException("attempt receipt still unavailable") }.use { }
        }
        assertTrue(journal.exists(), "startup must not remove the journal before attempt reconciliation succeeds")

        var reconciliations = 0
        ReconstructionOutputWorkspace.openForStartupRecovery(
            fixture.root, fixture.input, WorkflowStartupRecoveryBudget(WorkflowStartupRecoveryLimits()),
        ) { reconciliations++ }.use { }
        assertEquals(1, reconciliations)
        assertFalse(journal.exists())
        assertEquals(generationHashes(fixture.root, "candidate"), captureGeneration(fixture.root))
    }

    @Test
    fun `crash recovery never exposes a mixed multi-member generation`() {
        val members = setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions")
        val baseline = fixture("publication-multi-sync-baseline-")
        writeGeneration(baseline.root, "accepted")
        var successfulRootSyncs = 0
        assertEquals(PublicationResult.PUBLISHED, publish(baseline, members, { writeGeneration(it, "candidate") },
            syncDirectory = { directory -> if (directory == baseline.root) successfulRootSyncs++; sync(directory) }))
        assertTrue(successfulRootSyncs > 10, "fixture must pass through each multi-member rename and journal sync")
        val candidate = captureGeneration(baseline.root)

        for (failedRootSync in 5..successfulRootSyncs) {
            val fixture = fixture("publication-multi-crash-$failedRootSync-")
            writeGeneration(fixture.root, "accepted")
            val accepted = captureGeneration(fixture.root)
            var rootSyncs = 0
            val publication = runCatching {
                publish(fixture, members, { writeGeneration(it, "candidate") }, syncDirectory = { directory ->
                    if (directory == fixture.root && ++rootSyncs == failedRootSync) throw IOException("simulated interruption")
                    sync(directory)
                })
            }
            if (publication.getOrNull() == PublicationResult.PENDING) recover(fixture)
            if (publication.isFailure) {
                // Failures before the durable decision are rejected and recovered backward.
                assertEquals(accepted, captureGeneration(fixture.root), "pre-decision interruption at sync $failedRootSync")
            } else {
                val actual = captureGeneration(fixture.root)
                assertTrue(actual == accepted || actual == candidate,
                    "recovery at sync $failedRootSync must leave a complete generation")
            }
            val journal = fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION)
            if (journal.exists()) recover(fixture)
            val afterRecovery = captureGeneration(fixture.root)
            assertTrue(afterRecovery == accepted || afterRecovery == candidate,
                "recovery at sync $failedRootSync must restore or roll forward the entire generation")
            assertFalse(journal.exists())
        }
    }

    @Test
    fun `decision and each rename crash state recover by rolling forward`() {
        for (failedRootSync in 5..8) {
            val fixture = fixture("publication-matrix-")
            fixture.root.resolve("source-tree.zip").writeText("old")
            var rootSyncs = 0
            val result = publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") }, syncDirectory = { dir ->
                    if (dir == fixture.root && ++rootSyncs == failedRootSync) throw IOException("injected sync failure")
                    sync(dir)
                })

            assertEquals(PublicationResult.PENDING, result)
            recover(fixture)
            assertEquals("new", fixture.root.resolve("source-tree.zip").readText())
            assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
            assertFalse(Files.newDirectoryStream(fixture.root).use { stream -> stream.any {
                it.fileName.toString().startsWith(".reconstruction-stage-") ||
                    it.fileName.toString().startsWith(".reconstruction-previous-")
            } })
        }
    }

    @Test
    fun `startup recovery charges journal and tree traversal to its shared budget`() {
        val fixture = fixture("publication-startup-budget-")
        val accepted = ByteArray(32 * 1024) { (it % 251).toByte() }
        fixture.root.resolve("source-tree.zip").writeBytes(accepted)
        var rootSyncs = 0
        val result = publish(fixture, setOf("source-tree.zip"), {
            it.resolve("source-tree.zip").writeBytes(ByteArray(32 * 1024) { 7 })
        }, syncDirectory = { directory ->
            if (directory == fixture.root && ++rootSyncs == 5) throw IOException("decision sync")
            sync(directory)
        })
        assertEquals(PublicationResult.PENDING, result)
        val journal = fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION)
        val budget = WorkflowStartupRecoveryBudget(WorkflowStartupRecoveryLimits(
            maximumPublicationRecoveryEntries = 100,
            maximumPublicationRecoveryBytes = 8 * 1024,
        ))
        val refusal = assertFailsWith<decompengine.jobs.WorkflowStoreException> {
            ReconstructionOutputWorkspace.openForStartupRecovery(fixture.root, fixture.input, budget).use { }
        }
        assertEquals("STORE_LIMIT", refusal.code)
        assertTrue(journal.exists(), "budget exhaustion must retain the transaction journal")
        assertContentEquals(accepted, readCommittedFileWithoutAtime(fixture.root, "source-tree.zip"),
            "startup must refuse before mutating a generation it cannot fully inspect")
        assertTrue(budget.publicationRecoveryBytes <= 8 * 1024)

        val boundedButSufficient = WorkflowStartupRecoveryBudget(WorkflowStartupRecoveryLimits(
            maximumPublicationRecoveryEntries = 100,
            maximumPublicationRecoveryBytes = 160 * 1024,
        ))
        ReconstructionOutputWorkspace.openForStartupRecovery(fixture.root, fixture.input, boundedButSufficient).use { }
        assertFalse(journal.exists())
        assertContentEquals(ByteArray(32 * 1024) { 7 }, readCommittedFileWithoutAtime(fixture.root, "source-tree.zip"))
        assertTrue(boundedButSufficient.publicationRecoveryBytes <= 160 * 1024)
    }

    @Test
    fun `cancellation before decision preserves live bytes`() {
        val fixture = fixture("publication-cancel-")
        fixture.root.resolve("source-tree.zip").writeText("accepted")
        val result = publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("candidate") },
            cancellationCheck = { throw CancellationException("cancel") })
        assertEquals(PublicationResult.REJECTED, result)
        assertEquals("accepted", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        assertFalse(Files.newDirectoryStream(fixture.root).use { stream -> stream.any {
            it.fileName.toString().startsWith(".reconstruction-stage-") ||
                it.fileName.toString().startsWith(".reconstruction-previous-")
        } })
    }

    @Test
    fun `durable preparing intent recovers a partially built stage`() {
        val fixture = fixture("publication-preparing-recovery-")
        fixture.root.resolve("source-tree.zip").writeText("accepted")
        val txid = UUID.randomUUID().toString()
        val stage = fixture.root.resolve(".reconstruction-stage-$txid")
        val previous = fixture.root.resolve(".reconstruction-previous-$txid")
        Files.createDirectory(stage)
        Files.createDirectory(previous)
        Files.setPosixFilePermissions(stage, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(previous, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(stage.resolve("source-tree"))
        stage.resolve("source-tree/partial.c").writeText("interrupted candidate")
        writePreparingJournal(fixture, txid, "preparing", stage, previous)

        recover(fixture)

        assertEquals("accepted", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(stage.exists())
        assertFalse(previous.exists())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
    }

    @Test
    fun `preparing intent safely removes empty roots created before identities were journaled`() {
        val fixture = fixture("publication-preparing-unrecorded-roots-")
        fixture.root.resolve("source-tree.zip").writeText("accepted")
        val txid = UUID.randomUUID().toString()
        val stage = fixture.root.resolve(".reconstruction-stage-$txid")
        val previous = fixture.root.resolve(".reconstruction-previous-$txid")
        Files.createDirectory(stage)
        Files.createDirectory(previous)
        Files.setPosixFilePermissions(stage, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(previous, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        writePreparingJournal(fixture, txid, "preparing", stage, previous, recordRootIdentities = false)

        recover(fixture)

        assertEquals("accepted", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(stage.exists())
        assertFalse(previous.exists())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
    }

    @Test
    fun `preparing cleanup resumes when previous root was already removed`() {
        val fixture = fixture("publication-preparing-cleanup-recovery-")
        fixture.root.resolve("source-tree.zip").writeText("accepted")
        val txid = UUID.randomUUID().toString()
        val stage = fixture.root.resolve(".reconstruction-stage-$txid")
        val previous = fixture.root.resolve(".reconstruction-previous-$txid")
        Files.createDirectory(stage)
        Files.createDirectory(previous)
        Files.setPosixFilePermissions(stage, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(previous, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        Files.createDirectory(stage.resolve("source-tree"))
        stage.resolve("source-tree/partial.c").writeText("interrupted candidate")
        val previousIdentity = LinuxFilesystemSyscalls.openRoot(previous).use {
            it.identity.key.device.toString() to it.identity.key.inode.toString()
        }
        Files.delete(previous)
        writePreparingJournal(fixture, txid, "preparing-cleanup", stage, previous, previousIdentity)

        recover(fixture)

        assertEquals("accepted", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(stage.exists())
        assertFalse(previous.exists())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
    }

    @Test
    fun `interrupted journal sidecar without intent is safely removed`() {
        val fixture = fixture("publication-journal-sidecar-recovery-")
        val sidecar = fixture.root.resolve(".publication-${UUID.randomUUID()}.tmp")
        sidecar.writeText("partial journal")
        Files.setPosixFilePermissions(sidecar, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))

        recover(fixture)

        assertFalse(sidecar.exists())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
    }

    @Test
    fun `source and destination directories are synced after every rename`() {
        val fixture = fixture("publication-sync-order-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        val synced = mutableListOf<Path>()
        val result = publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") },
            syncDirectory = { dir -> synced.add(dir); sync(dir) })
        assertEquals(PublicationResult.PUBLISHED, result)
        val stage = synced.indexOfFirst { it.fileName.toString().startsWith(".reconstruction-stage-") }
        val previous = synced.indexOfFirst { it.fileName.toString().startsWith(".reconstruction-previous-") }
        assertTrue(stage >= 0 && previous >= 0)
        val firstRename = synced.withIndex().firstOrNull { it.index >= 3 && it.value == fixture.root }?.index ?: -1
        assertTrue(firstRename >= 0)
        val previousPath = synced[previous]
        val stagePath = synced[stage]
        val oldDestinationSync = synced.indexOf(previousPath)
        val newSourceSync = synced.withIndex().first { it.index > oldDestinationSync && it.value == stagePath }.index
        assertTrue(synced.drop(firstRename + 1).any { it == previousPath })
        assertTrue(synced.drop(oldDestinationSync + 1).any { it == stagePath })
        assertTrue(synced.drop(newSourceSync + 1).any { it == fixture.root })
    }

    @Test
    fun `cooperating readers wait through the multi-member publication window`() {
        val fixture = fixture("publication-reader-lease-")
        Files.createDirectory(fixture.root.resolve("source-tree"))
        fixture.root.resolve("source-tree/value.c").writeText("old-source")
        fixture.root.resolve("source-tree.zip").writeText("old-archive")
        fixture.root.resolve("reconstruction.json").writeText("old-metadata")
        val readerStarted = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        var reader: java.util.concurrent.Future<List<String>>? = null
        var injected = false
        try {
            val result = publish(
                fixture,
                setOf("source-tree", "source-tree.zip", "reconstruction.json"),
                { stage ->
                    Files.createDirectory(stage.resolve("source-tree"))
                    stage.resolve("source-tree/value.c").writeText("new-source")
                    stage.resolve("source-tree.zip").writeText("new-archive")
                    stage.resolve("reconstruction.json").writeText("new-metadata")
                },
                syncDirectory = { directory ->
                    if (!injected && directory == fixture.root &&
                        !fixture.root.resolve("source-tree").exists() &&
                        Files.newDirectoryStream(fixture.root).use { stream -> stream.any {
                            it.fileName.toString().startsWith(".reconstruction-previous-") &&
                                it.resolve("source-tree").exists()
                        } }) {
                        injected = true
                        reader = executor.submit<List<String>> {
                            readerStarted.countDown()
                            ReconstructionOutputWorkspace.withReadLease(fixture.root) {
                                listOf(
                                    fixture.root.resolve("source-tree/value.c").readText(),
                                    fixture.root.resolve("source-tree.zip").readText(),
                                    fixture.root.resolve("reconstruction.json").readText(),
                                )
                            }
                        }
                        assertTrue(readerStarted.await(2, TimeUnit.SECONDS))
                        assertFalse(requireNotNull(reader).isDone, "reader must wait while live names are being replaced")
                    }
                    sync(directory)
                },
            )
            assertEquals(PublicationResult.PUBLISHED, result)
            assertTrue(injected, "the reader must start while the old live member has moved away")
            assertEquals(listOf("new-source", "new-archive", "new-metadata"),
                requireNotNull(reader).get(5, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `ordinary job artifact reads join the publication lease`() {
        val base = createTempDirectory("publication-job-artifact-reader-")
        val store = JobStore(base.resolve("jobs"))
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val reports = store.reportsDirectory(job.id)
        val input = base.resolve("model-input.bin").apply { writeText("admitted model input") }
        Files.createDirectory(reports.resolve("source-tree"))
        reports.resolve("source-tree/value.c").writeText("old-source")
        reports.resolve("source-tree.zip").writeText("old-archive")
        reports.resolve("reconstruction.json").writeText("old-metadata")
        Files.createDirectories(reports.resolve(".decomp-agent-sessions"))
        reports.resolve(".decomp-agent-sessions/session.json").writeText("old-session")
        reports.resolve(ReconstructionOutputWorkspace.ACTIVE).writeText(
            "{\"schemaVersion\":1,\"inputSha256\":\"${sha256(input.readBytes())}\"}",
        )
        val readerStarted = CountDownLatch(2)
        val executor = Executors.newFixedThreadPool(2)
        var sourceReader: java.util.concurrent.Future<String>? = null
        var sessionReader: java.util.concurrent.Future<String>? = null
        var injected = false
        var readersStartedWhileReplacing = false
        var readersWaitedForPublication = false
        try {
            ReconstructionOutputWorkspace.openWithParentSyncForTest(reports, input) { directory ->
                if (!injected && directory == reports && !reports.resolve("source-tree").exists() &&
                    Files.newDirectoryStream(reports).use { entries -> entries.any {
                        it.fileName.toString().startsWith(".reconstruction-previous-") && it.resolve("source-tree").exists()
                    } }) {
                    injected = true
                    sourceReader = executor.submit<String> {
                        readerStarted.countDown()
                        store.readArtifact(job.id, "reports/source-tree.zip", 1024).bytes.toString(Charsets.UTF_8)
                    }
                    sessionReader = executor.submit<String> {
                        readerStarted.countDown()
                        store.readArtifact(job.id, "reports/.decomp-agent-sessions/session.json", 1024)
                            .bytes.toString(Charsets.UTF_8)
                    }
                    readersStartedWhileReplacing = readerStarted.await(2, TimeUnit.SECONDS)
                    readersWaitedForPublication = !requireNotNull(sourceReader).isDone && !requireNotNull(sessionReader).isDone
                }
                sync(directory)
            }.use { workspace ->
                val result = workspace.publish(
                    setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions"),
                    { stage ->
                        Files.createDirectory(stage.resolve("source-tree"))
                        stage.resolve("source-tree/value.c").writeText("new-source")
                        stage.resolve("source-tree.zip").writeText("new-archive")
                        stage.resolve("reconstruction.json").writeText("new-metadata")
                        Files.createDirectories(stage.resolve(".decomp-agent-sessions"))
                        stage.resolve(".decomp-agent-sessions/session.json").writeText("new-session")
                    },
                )
                assertEquals(PublicationResult.PUBLISHED, result)
            }
            assertTrue(injected, "the normal artifact read must start while live members are replaced")
            assertTrue(readersStartedWhileReplacing, "both artifact readers must start inside the replacement window")
            assertTrue(readersWaitedForPublication, "artifact readers must remain leased until publication completes")
            assertEquals("new-archive", requireNotNull(sourceReader).get(5, TimeUnit.SECONDS))
            assertEquals("new-session", requireNotNull(sessionReader).get(5, TimeUnit.SECONDS))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `ambiguous journal unlink sync reinstalls pending journal`() {
        val fixture = fixture("publication-journal-unlink-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        var rootSyncs = 0
        val result = publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") }, syncDirectory = { dir ->
                if (dir == fixture.root && ++rootSyncs == 11) throw IOException("journal unlink sync")
                sync(dir)
            })
        assertEquals(PublicationResult.PENDING, result)
        assertTrue(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        recover(fixture)
        assertEquals("new", readCommittedFileWithoutAtime(fixture.root, "source-tree.zip").decodeToString())
    }

    @Test
    fun `aborting cleanup resumes after previous root deletion`() {
        val fixture = fixture("publication-abort-resume-")
        fixture.root.resolve("source-tree.zip").writeText("accepted")
        var rootSyncs = 0
        val result = publish(
            fixture,
            setOf("source-tree.zip"),
            { it.resolve("source-tree.zip").writeText("candidate") },
            cancellationCheck = { throw CancellationException("cancel before decision") },
            syncDirectory = { directory ->
                if (directory == fixture.root && ++rootSyncs == 6) throw IOException("abort cleanup interruption")
                sync(directory)
            },
        )
        assertEquals(PublicationResult.PENDING, result)
        assertTrue(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        recover(fixture)
        assertEquals("accepted", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        assertFalse(Files.newDirectoryStream(fixture.root).use { stream -> stream.any {
            it.fileName.toString().startsWith(".reconstruction-stage-") ||
                it.fileName.toString().startsWith(".reconstruction-previous-")
        } })
    }

    @Test
    fun `swapped cleanup resumes after previous root deletion`() {
        val fixture = fixture("publication-swap-cleanup-resume-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        var rootSyncs = 0
        val result = publish(
            fixture,
            setOf("source-tree.zip"),
            { it.resolve("source-tree.zip").writeText("new") },
            syncDirectory = { directory ->
                if (directory == fixture.root && ++rootSyncs == 9) throw IOException("swapped cleanup interruption")
                sync(directory)
            },
        )
        assertEquals(PublicationResult.PENDING, result)
        assertEquals("new", readCommittedFileWithoutAtime(fixture.root, "source-tree.zip").decodeToString())
        assertTrue(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        recover(fixture)
        assertEquals("new", fixture.root.resolve("source-tree.zip").readText())
        assertFalse(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
    }

    @Test
    fun `corrupt journal and conflicting location refuse recovery without dropping evidence`() {
        val fixture = fixture("publication-corrupt-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        var rootSyncs = 0
        val result = publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") }, syncDirectory = { dir ->
                if (dir == fixture.root && ++rootSyncs == 5) throw IOException("decision sync")
                sync(dir)
            })
        assertEquals(PublicationResult.PENDING, result)
        val journal = fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION)
        val original = journal.readBytes()
        val originalText = original.toString(Charsets.UTF_8)
        val wrongBoolean = originalText.replaceFirst("\"present\":true", "\"present\":\"true\"")
        assertNotEquals(originalText, wrongBoolean)
        journal.writeText(wrongBoolean)
        assertFails { recover(fixture) }
        assertTrue(journal.exists())
        val modeMatch = checkNotNull(Regex("\"mode\":([0-9]+)").find(originalText))
        val wrongInteger = originalText.replaceRange(
            modeMatch.range,
            "\"mode\":\"${modeMatch.groupValues[1]}\"",
        )
        assertNotEquals(originalText, wrongInteger)
        journal.writeText(wrongInteger)
        assertFails { recover(fixture) }
        assertTrue(journal.exists())
        journal.writeText("{")
        assertFails { recover(fixture) }
        assertTrue(journal.exists())
        journal.writeBytes(original)

        val stage = Files.newDirectoryStream(fixture.root).use { stream -> stream.first { it.fileName.toString().startsWith(".reconstruction-stage-") } }
        stage.resolve("source-tree.zip").writeText("tampered")
        assertFails { recover(fixture) }
        assertTrue(journal.exists())
        assertEquals("old", fixture.root.resolve("source-tree.zip").readText())
    }

    @Test
    fun `stage rejects unsafe links and over-depth trees before decision`() {
        val fixture = fixture("publication-unsafe-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        assertFails {
            publish(fixture, setOf("source-tree.zip"), { stage ->
                    Files.createSymbolicLink(stage.resolve("source-tree.zip"), fixture.root.resolve("source-tree.zip"))
                })
        }
        assertEquals("old", fixture.root.resolve("source-tree.zip").readText())

        val outside = fixture.scratch.resolve("publication-hardlink-source").apply { writeText("linked") }
        assertFails {
            publish(fixture, setOf("source-tree.zip"), { stage -> Files.createLink(stage.resolve("source-tree.zip"), outside) })
        }
        assertEquals("old", fixture.root.resolve("source-tree.zip").readText())

        assertFails {
            publish(fixture, setOf("source-tree"), { stage ->
                    var cursor = stage.resolve("source-tree")
                    Files.createDirectory(cursor)
                    repeat(65) { cursor = cursor.resolve("d"); Files.createDirectory(cursor) }
                })
        }
        assertEquals("old", fixture.root.resolve("source-tree.zip").readText())
    }

    @Test
    fun `tree commitments are deterministic framed and bind nested identities`() {
        val fixture = fixture("publication-commitment-")
        val first = Files.createDirectory(fixture.root.resolve("first"))
        Files.createDirectory(first.resolve("a"))
        first.resolve("a").resolve("bc").writeText("payload")
        val second = Files.createDirectory(fixture.root.resolve("second"))
        Files.createDirectory(second.resolve("ab"))
        second.resolve("ab").resolve("c").writeText("payload")

        fun commitment(name: String): PublicationEntryRecord = LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of(name), PublicationTreeBudget())
        }

        val directoryAtimeBefore = Files.readAttributes(first, java.nio.file.attribute.BasicFileAttributes::class.java)
            .lastAccessTime()
        val firstRecord = commitment("first")
        val directoryAtimeAfter = Files.readAttributes(first, java.nio.file.attribute.BasicFileAttributes::class.java)
            .lastAccessTime()
        assertEquals(directoryAtimeBefore, directoryAtimeAfter, "directory enumeration must preserve atime")
        assertEquals(0L, firstRecord.atimeSeconds, "directory atime is excluded from the stable commitment")
        assertEquals(0, firstRecord.atimeNanoseconds)
        Files.setAttribute(first, "basic:lastAccessTime", java.nio.file.attribute.FileTime.fromMillis(2_000), NOFOLLOW_LINKS)
        assertEquals(firstRecord.commitment, commitment("first").commitment,
            "directory atime is observation state, not an authoritative publication field")
        assertEquals(firstRecord, commitment("first"))
        val secondRecord = commitment("second")
        assertNotEquals(firstRecord.commitment, secondRecord.commitment)

        val duplicateTree = Files.createDirectory(fixture.root.resolve("duplicate"))
        Files.createDirectory(duplicateTree.resolve("a"))
        duplicateTree.resolve("a").resolve("bc").writeText("payload")
        assertNotEquals(firstRecord.commitment, commitment("duplicate").commitment)

        val exhaustedEntries = PublicationTreeBudget(entries = ReconstructionOutputTree.MAX_ENTRIES)
        assertFails { LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of("first"), exhaustedEntries)
        } }
        val exhaustedBytes = PublicationTreeBudget(bytes = ReconstructionOutputTree.MAX_BYTES)
        assertFails { LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of("first"), exhaustedBytes)
        } }
    }

    @Test
    fun `directory atime changes during commitment do not look like content mutation`() {
        val fixture = fixture("publication-directory-atime-race-")
        val tree = Files.createDirectory(fixture.root.resolve("tree"))
        tree.resolve("member.txt").writeText("payload")
        Files.setAttribute(tree, "basic:lastAccessTime",
            java.nio.file.attribute.FileTime.fromMillis(2_000), NOFOLLOW_LINKS)
        val before = Files.readAttributes(tree, java.nio.file.attribute.BasicFileAttributes::class.java,
            NOFOLLOW_LINKS).lastAccessTime()
        var visited = 0
        val budget = PublicationTreeBudget(accountEntry = {
            if (++visited == 2) {
                // Force an ordinary enumeration after recordEntry captured directory state but
                // before it verifies that state after traversing the child.
                Files.newDirectoryStream(tree).use { entries -> entries.forEach { } }
            }
        })

        val record = LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of("tree"), budget)
        }

        val after = Files.readAttributes(tree, java.nio.file.attribute.BasicFileAttributes::class.java,
            NOFOLLOW_LINKS).lastAccessTime()
        assertTrue(visited >= 2, "the ordinary enumeration must happen inside the commitment walk")
        assertNotEquals(before, after, "the control must change directory atime")
        assertEquals("directory", record.type)
        assertEquals(0L, record.atimeSeconds, "directory atime is excluded from its stable commitment")
        assertEquals(0, record.atimeNanoseconds)
    }

    @Test
    fun `metadata commitment binds ownership timestamps and inode identity`() {
        val fixture = fixture("publication-metadata-commitment-")
        val file = fixture.root.resolve("metadata.bin").apply { writeText("same bytes") }
        fun record() = LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of("metadata.bin"), PublicationTreeBudget())
        }

        val original = record()
        assertEquals(Files.getAttribute(file, "unix:uid") as Int, original.uid)
        assertEquals(Files.getAttribute(file, "unix:gid") as Int, original.gid)
        assertEquals(1, original.linkCount)
        assertEquals(Files.size(file), original.size)
        assertTrue(original.metadataVerified)
        assertNotEquals(record(), original.copy(uid = original.uid + 1), "recovery equality must reject changed uid")
        assertNotEquals(record(), original.copy(gid = original.gid + 1), "recovery equality must reject changed gid")

        Files.setLastModifiedTime(file, java.nio.file.attribute.FileTime.from(1_700_000_000L, java.util.concurrent.TimeUnit.SECONDS))
        val changedTime = record()
        assertNotEquals(original.commitment, changedTime.commitment)
        assertNotEquals(original.mtimeSeconds, changedTime.mtimeSeconds)
        val accessTimeBeforeRead = Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes::class.java)
            .lastAccessTime().toInstant()
        val changedAccessTime = record()
        val accessTimeAfterRead = Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes::class.java)
            .lastAccessTime().toInstant()
        assertEquals(accessTimeBeforeRead.epochSecond, changedAccessTime.atimeSeconds)
        assertEquals(accessTimeBeforeRead, accessTimeAfterRead, "commitment reads must preserve file atime")

        val replacementFile = fixture.root.resolve("replacement.tmp").apply { writeText("same bytes") }
        Files.move(replacementFile, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
        val replacement = record()
        assertNotEquals(changedAccessTime.ino, replacement.ino)
        assertNotEquals(changedAccessTime.commitment, replacement.commitment)
    }

    @Test
    fun `xattr policy rejects presence without reading values`() {
        val fixture = fixture("publication-xattr-policy-")
        val file = fixture.root.resolve("with-xattr").apply { writeText("payload") }
        val attributes = Files.getFileAttributeView(file, java.nio.file.attribute.UserDefinedFileAttributeView::class.java)
        try {
            attributes.write("publication-policy", java.nio.ByteBuffer.wrap(byteArrayOf(1, 2, 3)))
        } catch (_: UnsupportedOperationException) {
            return
        } catch (_: IOException) {
            return
        }
        assertFails {
            LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
                ReconstructionOutputTree.recordAt(root, Path.of("with-xattr"), PublicationTreeBudget())
            }
        }
    }

    @Test
    fun `tree hashing never reads beyond the size reserved before concurrent growth`() {
        val fixture = fixture("publication-growing-file-budget-")
        val content = ByteArray(256 * 1024) { (it % 239).toByte() }
        val file = fixture.root.resolve("growing.bin").apply { writeBytes(content) }
        var reservedBytes = 0L
        var grew = false
        val budget = PublicationTreeBudget(
            accountBytes = { reservedBytes = Math.addExact(reservedBytes, it) },
            checkpoint = {
                if (!grew) {
                    grew = true
                    Files.write(file, ByteArray(2 * 1024 * 1024) { 0x5c }, java.nio.file.StandardOpenOption.APPEND)
                }
            },
        )

        assertFails { LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.recordAt(root, Path.of("growing.bin"), budget)
        } }
        assertTrue(grew)
        assertEquals(content.size.toLong(), reservedBytes)
        assertEquals(content.size.toLong(), budget.bytes,
            "growing content must be rejected without reading or hashing beyond its reserved size")
        assertEquals(content.size.toLong() + 2 * 1024 * 1024, Files.size(file))
    }

    @Test
    fun `duplicate or conflicting post-decision locations refuse and retain journal`() {
        val fixture = fixture("publication-conflict-")
        fixture.root.resolve("source-tree.zip").writeText("old")
        var rootSyncs = 0
        assertEquals(PublicationResult.PENDING, publish(fixture, setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") }, syncDirectory = { dir ->
                if (dir == fixture.root && ++rootSyncs == 5) throw IOException("after decision")
                sync(dir)
            }))
        val journalRecord = Json.parseToJsonElement(
            fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).readText(),
        ).jsonObject
        assertEquals(4, journalRecord.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(1, journalRecord.getValue("metadataVersion").jsonPrimitive.int)
        assertEquals("NONE", journalRecord.getValue("xattrPolicy").jsonPrimitive.content)
        assertTrue(journalRecord.getValue("new").jsonObject.getValue("source-tree.zip").jsonObject.keys
            .containsAll(setOf("uid", "gid", "nlink", "size", "atimeSec", "atimeNanos", "mtimeSec", "mtimeNanos", "metadataVerified")))
        val stage = Files.newDirectoryStream(fixture.root).use { it.first { child -> child.fileName.toString().startsWith(".reconstruction-stage-") } }
        val previous = Files.newDirectoryStream(fixture.root).use { it.first { child -> child.fileName.toString().startsWith(".reconstruction-previous-") } }
        Files.copy(fixture.root.resolve("source-tree.zip"), previous.resolve("source-tree.zip"))
        assertFails { recover(fixture) }
        assertTrue(fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        assertTrue(stage.exists())
    }

    private data class Fixture(val scratch: Path, val root: Path, val input: Path)

    private fun fixture(prefix: String): Fixture {
        val scratch = createTempDirectory(prefix)
        val root = Files.createDirectory(scratch.resolve("reports"))
        val input = scratch.resolve("input.bin").apply { writeText("authenticated input") }
        // Seed the active identity before tests add archival members; otherwise activation quite
        // correctly treats those members as belonging to an unidentified input and switches them.
        ReconstructionOutputWorkspace.open(root, input).use { }
        return Fixture(scratch, root, input)
    }

    private fun <T> withWorkspace(fixture: Fixture, block: (ReconstructionOutputWorkspace) -> T): T =
        withWorkspace(fixture, ::sync, block)

    private fun <T> withWorkspace(
        fixture: Fixture,
        syncDirectory: (Path) -> Unit,
        block: (ReconstructionOutputWorkspace) -> T,
    ): T = ReconstructionOutputWorkspace.openWithParentSyncForTest(fixture.root, fixture.input, syncDirectory).use(block)

    private fun publish(
        fixture: Fixture,
        members: Set<String>,
        buildStage: (Path) -> Unit,
        cancellationCheck: () -> Unit = {},
        syncDirectory: (Path) -> Unit = ::sync,
    ): PublicationResult = withWorkspace(fixture, syncDirectory) { workspace ->
        workspace.publish(members, buildStage, cancellationCheck)
    }

    private fun recover(fixture: Fixture) {
        withWorkspace(fixture) { /* Opening activates and recovers before returning. */ }
    }

    private fun writeGeneration(root: Path, label: String) {
        Files.createDirectories(root.resolve("source-tree/reports"))
        Files.createDirectories(root.resolve(".decomp-agent-sessions"))
        root.resolve("source-tree/module.c").writeText("$label source\n")
        root.resolve("source-tree/reports/build_contract.json").writeText("{\"generation\":\"$label\"}\n")
        root.resolve("source-tree.zip").writeText("$label archive\n")
        root.resolve("reconstruction.json").writeText("{\"generation\":\"$label\"}\n")
        root.resolve(".decomp-agent-sessions/session.json").writeText("{\"generation\":\"$label\"}\n")
    }

    private fun captureGeneration(root: Path): Map<String, String> {
        val names = listOf(
            "source-tree/module.c",
            "source-tree/reports/build_contract.json",
            "source-tree.zip",
            "reconstruction.json",
            ".decomp-agent-sessions/session.json",
        )
        return names.associateWith { relative -> sha256(readCommittedFileWithoutAtime(root, relative)) }
    }

    private fun captureGenerationMetadata(root: Path): Map<String, PublicationEntryRecord> {
        val members = listOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions")
        val budget = PublicationTreeBudget()
        return LinuxFilesystemSyscalls.openRoot(root).use { descriptor ->
            members.associateWith { member ->
                ReconstructionOutputTree.recordAt(descriptor, Path.of(member), budget)
            }
        }
    }

    private fun readCommittedFileWithoutAtime(root: Path, relative: String): ByteArray {
        val parts = relative.split('/')
        val directories = mutableListOf<decompengine.acp.LinuxDescriptor>()
        var file: decompengine.acp.LinuxDescriptor? = null
        var readable: decompengine.acp.LinuxDescriptor? = null
        try {
            var parent = LinuxFilesystemSyscalls.openRoot(root)
            directories += parent
            parts.dropLast(1).forEach { component ->
                parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component)
                directories += parent
            }
            file = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, parts.last()))
            readable = LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(requireNotNull(file))
            return LinuxFilesystemSyscalls.read(requireNotNull(readable), 4 * 1024 * 1024) {}
        } finally {
            readable?.close()
            file?.close()
            directories.asReversed().forEach { it.close() }
        }
    }

    private fun generationHashes(root: Path, label: String): Map<String, String> = mapOf(
        "source-tree/module.c" to sha256("$label source\n".toByteArray()),
        "source-tree/reports/build_contract.json" to sha256("{\"generation\":\"$label\"}\n".toByteArray()),
        "source-tree.zip" to sha256("$label archive\n".toByteArray()),
        "reconstruction.json" to sha256("{\"generation\":\"$label\"}\n".toByteArray()),
        ".decomp-agent-sessions/session.json" to sha256("{\"generation\":\"$label\"}\n".toByteArray()),
    )

    private fun sync(path: Path) {
        java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ, NOFOLLOW_LINKS).use { it.force(true) }
    }

    private fun writePreparingJournal(
        fixture: Fixture,
        txid: String,
        phase: String,
        stage: Path,
        previous: Path,
        previousIdentityOverride: Pair<String, String>? = null,
        recordRootIdentities: Boolean = true,
    ) {
        fun identity(path: Path): Pair<String, String> = LinuxFilesystemSyscalls.openRoot(path).use {
            it.identity.key.device.toString() to it.identity.key.inode.toString()
        }
        fun identityJson(value: Pair<String, String>) = buildJsonObject {
            put("dev", value.first); put("ino", value.second)
        }
        val old = LinuxFilesystemSyscalls.openRoot(fixture.root).use { root ->
            ReconstructionOutputTree.legacyRecordAt(root, Path.of("source-tree.zip"), PublicationTreeBudget())
        }
        val journal = buildJsonObject {
            put("schemaVersion", 3)
            put("txid", txid)
            put("inputSha256", java.security.MessageDigest.getInstance("SHA-256")
                .digest("authenticated input".toByteArray()).joinToString("") { "%02x".format(it) })
            put("phase", phase)
            put("members", buildJsonArray { add(JsonPrimitive("source-tree.zip")) })
            put("root", identityJson(identity(fixture.root)))
            put("stage", if (recordRootIdentities) identityJson(identity(stage)) else JsonNull)
            put("previous", if (recordRootIdentities) identityJson(previousIdentityOverride ?: identity(previous)) else JsonNull)
            fun record(value: PublicationEntryRecord) = buildJsonObject {
                put("present", value.present); put("type", value.type); put("mode", value.mode)
                put("dev", value.dev); put("ino", value.ino); put("commitment", value.commitment)
            }
            put("old", buildJsonObject { put("source-tree.zip", record(old)) })
            put("new", buildJsonObject { })
        }
        val journalPath = fixture.root.resolve(ReconstructionOutputWorkspace.PUBLICATION)
        journalPath.writeText(journal.toString())
        Files.setPosixFilePermissions(journalPath, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
    }
}

/** Abrupt owner-process death after a durable live rename; the parent must recover from journal state. */
object ReconstructionOutputPublicationCrashFixture {
    @JvmStatic
    fun main(args: Array<String>) {
        val root = Path.of(args[0])
        val input = Path.of(args[1])
        val crashAfterRootSync = args[2].toInt()
        var rootSyncs = 0
        val result = ReconstructionOutputWorkspace.openWithParentSyncForTest(root, input) { directory ->
            java.nio.channels.FileChannel.open(directory, java.nio.file.StandardOpenOption.READ, NOFOLLOW_LINKS)
                .use { it.force(true) }
            if (directory == root && ++rootSyncs == crashAfterRootSync) Runtime.getRuntime().halt(86)
        }.use { workspace ->
            workspace.publish(setOf("source-tree", "source-tree.zip", "reconstruction.json", ".decomp-agent-sessions"), { stage ->
                Files.createDirectories(stage.resolve("source-tree/reports"))
                Files.createDirectories(stage.resolve(".decomp-agent-sessions"))
                stage.resolve("source-tree/module.c").writeText("candidate source\n")
                stage.resolve("source-tree/reports/build_contract.json").writeText("{\"generation\":\"candidate\"}\n")
                stage.resolve("source-tree.zip").writeText("candidate archive\n")
                stage.resolve("reconstruction.json").writeText("{\"generation\":\"candidate\"}\n")
                stage.resolve(".decomp-agent-sessions/session.json").writeText("{\"generation\":\"candidate\"}\n")
            })
        }
        if (result == PublicationResult.PUBLISHED) kotlin.system.exitProcess(87)
        kotlin.system.exitProcess(88)
    }
}
