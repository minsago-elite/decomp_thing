package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import java.util.concurrent.Executors
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.jobs.WorkflowStartupRecoveryBudget
import decompengine.jobs.WorkflowStartupRecoveryLimits
import decompengine.jobs.WorkflowStoreException
import org.junit.jupiter.api.extension.ExtendWith
import kotlinx.serialization.json.*
import kotlin.io.path.*
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class ReconstructionOutputWorkspaceTest {
    @Test
    fun `startup publication recovery accounts input hashing before journal traversal`() {
        val base = createTempDirectory("input-publication-recovery-budget-")
        val input = base.resolve("input").apply { writeBytes(ByteArray(128 * 1024) { 0x5a }) }
        val root = base.resolve("output")
        val budget = WorkflowStartupRecoveryBudget(
            WorkflowStartupRecoveryLimits(maximumPublicationRecoveryBytes = 64 * 1024),
        )

        val refused = assertFailsWith<WorkflowStoreException> {
            ReconstructionOutputWorkspace.openForStartupRecovery(root, input, budget)
        }
        assertEquals("STORE_LIMIT", refused.code)
        assertEquals(0, budget.publicationRecoveryBytes, "an over-budget input is refused before its bytes are read")
        ReconstructionOutputWorkspace.open(root, input).use { }
    }

    @Test
    fun `startup input hashing checks cancellation between bounded reads and releases admission`() {
        val base = createTempDirectory("input-publication-recovery-cancel-")
        val input = base.resolve("input").apply { writeBytes(ByteArray(2 * 1024 * 1024) { 0x2a }) }
        val root = base.resolve("output")
        var checkpoints = 0
        val budget = WorkflowStartupRecoveryBudget(cancellation = { ++checkpoints >= 5 })

        val cancelled = assertFailsWith<WorkflowStoreException> {
            ReconstructionOutputWorkspace.openForStartupRecovery(root, input, budget)
        }
        assertEquals("RECOVERY_CANCELLED", cancelled.code)
        assertTrue(checkpoints >= 5)
        ReconstructionOutputWorkspace.open(root, input).use { }
    }

    @Test
    fun `workspace admission hashes input without changing committed atime`() {
        val base = createTempDirectory("input-publication-atime-")
        val input = base.resolve("input")
        val contents = ByteArray(192 * 1024) { (it % 251).toByte() }
        input.writeBytes(contents)
        val requestedAtime = java.time.Instant.ofEpochSecond(1_234_567_890L, 123_456_789)
        Files.setAttribute(input, "basic:lastAccessTime",
            java.nio.file.attribute.FileTime.from(requestedAtime), java.nio.file.LinkOption.NOFOLLOW_LINKS)
        val expectedAtime = Files.readAttributes(input, java.nio.file.attribute.BasicFileAttributes::class.java,
            java.nio.file.LinkOption.NOFOLLOW_LINKS).lastAccessTime()

        ReconstructionOutputWorkspace.open(base.resolve("output"), input).use { workspace ->
            assertEquals(sha256(contents), workspace.inputSha256)
        }

        val observedAtime = Files.readAttributes(input, java.nio.file.attribute.BasicFileAttributes::class.java,
            java.nio.file.LinkOption.NOFOLLOW_LINKS).lastAccessTime()
        assertEquals(expectedAtime, observedAtime, "admission hashing must not mutate the input metadata it commits")
    }

    @Test
    fun `CLI repair project lease waits for publication and reads only after writer closes`() {
        val base = createTempDirectory("input-project-read-lease-")
        val input = base.resolve("input").apply { writeText("input") }
        val root = base.resolve("output")
        val workspace = ReconstructionOutputWorkspace.open(root, input)
        Files.createDirectories(root.resolve("source-tree"))
        val executor = Executors.newFixedThreadPool(2)
        val entered = CountDownLatch(1)
        try {
            val read = executor.submit<Int> {
                entered.countDown()
                ReconstructionOutputWorkspace.withProjectReadLease(root.resolve("source-tree")) { 7 }
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertFails { read.get(100, TimeUnit.MILLISECONDS) }
            workspace.close()
            assertEquals(7, read.get(5, TimeUnit.SECONDS))
        } finally {
            runCatching { workspace.close() }
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `nested source read lease proceeds when a publication writer is queued`() {
        val base = createTempDirectory("nested-publication-read-")
        val input = base.resolve("input").apply { writeText("input") }
        val root = base.resolve("output")
        ReconstructionOutputWorkspace.open(root, input).close()
        val outerAcquired = CountDownLatch(1)
        val requestNested = CountDownLatch(1)
        val nestedAcquired = CountDownLatch(1)
        val releaseOuter = CountDownLatch(1)
        val writerStarted = CountDownLatch(1)
        val outerLease = java.util.concurrent.atomic.AtomicReference<AutoCloseable?>()
        val readerFailure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val writerFailure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val reader = Thread {
            try {
                val lease = ReconstructionOutputWorkspace.acquireReadLease(root)
                outerLease.set(lease)
                outerAcquired.countDown()
                check(requestNested.await(5, TimeUnit.SECONDS))
                ReconstructionOutputWorkspace.withReadLease(root) { Unit }
                nestedAcquired.countDown()
                check(releaseOuter.await(5, TimeUnit.SECONDS))
                lease.close()
            } catch (failure: Throwable) { readerFailure.set(failure) }
        }
        val writer = Thread {
            try {
                writerStarted.countDown()
                ReconstructionOutputWorkspace.open(root, input).use { }
            } catch (failure: Throwable) { writerFailure.set(failure) }
        }
        reader.start()
        try {
            assertTrue(outerAcquired.await(5, TimeUnit.SECONDS))
            writer.start()
            assertTrue(writerStarted.await(5, TimeUnit.SECONDS))
            val waitDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (writer.state !in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING) && System.nanoTime() < waitDeadline)
                Thread.yield()
            assertTrue(writer.state in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING),
                "publication writer did not block behind the outer read lease")
            requestNested.countDown()
            val nestedWasReentrant = nestedAcquired.await(2, TimeUnit.SECONDS)
            // Always release the outer lease, including on the regression path, so this test
            // cannot strand its worker threads if a nested acquisition queues behind the writer.
            outerLease.get()?.close()
            releaseOuter.countDown()
            reader.join(5_000)
            writer.join(5_000)
            assertTrue(nestedWasReentrant, "nested read must reuse its thread's existing read hold")
            assertFalse(reader.isAlive, "nested reader did not finish")
            assertFalse(writer.isAlive, "queued publisher did not finish")
            assertNull(readerFailure.get())
            assertNull(writerFailure.get())
        } finally {
            outerLease.get()?.close()
            requestNested.countDown()
            releaseOuter.countDown()
            reader.join(5_000)
            if (writer.state != Thread.State.NEW) writer.join(5_000)
            assertFalse(reader.isAlive, "reader worker leaked")
            assertFalse(writer.isAlive, "writer worker leaked")
        }
    }

    @Test
    fun `readers refuse retained input switch and replaced lock authority`() {
        val base = createTempDirectory("publication-read-authority-")
        val root = base.resolve("reports")
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(root, input).use { }
        val sourceTree = Files.createDirectories(root.resolve("source-tree"))
        val alias = base.resolve("renamed-project-alias")
        Files.createSymbolicLink(alias, sourceTree.toAbsolutePath())

        root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText("incomplete")
        var aliasActionRan = false
        assertFailsWith<ReconstructionOutputReadUnavailableException> {
            ReconstructionOutputWorkspace.withProjectReadLease(alias) { aliasActionRan = true }
        }
        assertFalse(aliasActionRan, "a differently named symlink must still be recognized as published source")
        Files.delete(root.resolve(ReconstructionOutputWorkspace.SWITCH))

        var admittedPath: Path? = null
        ReconstructionOutputWorkspace.withProjectReadLease(alias) { admittedPath = it }
        assertEquals(sourceTree.toRealPath(), admittedPath)

        ReconstructionOutputWorkspace.withProjectReadLease(sourceTree) { _ ->
            val lock = root.resolve(".reconstruction.lock")
            Files.move(lock, root.resolve("lock-original"), ATOMIC_MOVE)
            lock.writeText("replacement")
            assertFailsWith<ReconstructionOutputReadUnavailableException> {
                ReconstructionOutputWorkspace.withProjectReadLease(sourceTree) { Unit }
            }
        }
    }

    @Test
    fun `published project repair takes exclusive lease and blocks cooperating readers`() {
        val base = createTempDirectory("publication-mutation-lease-")
        val reports = Files.createDirectories(base.resolve("reports"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reports, input).use { }
        val sourceTree = Files.createDirectories(reports.resolve("source-tree"))
        val executor = Executors.newFixedThreadPool(2)
        val entered = java.util.concurrent.CountDownLatch(1)
        val readerStarted = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val blockedReader = java.util.concurrent.atomic.AtomicReference<java.util.concurrent.Future<*>>()
        try {
            val mutation = executor.submit {
                ReconstructionOutputWorkspace.withProjectMutationLease(sourceTree, { true }) {
                    entered.countDown()
                    release.await()
                }
            }
            if (!entered.await(5, TimeUnit.SECONDS)) mutation.get(1, TimeUnit.SECONDS)
            val read = executor.submit {
                readerStarted.countDown()
                check(ReconstructionOutputWorkspace.withReadLease(reports) { 1 } == 1)
            }
            blockedReader.set(read)
            assertTrue(readerStarted.await(5, TimeUnit.SECONDS))
            assertFails { read.get(100, TimeUnit.MILLISECONDS) }
            release.countDown()
            mutation.get(5, TimeUnit.SECONDS)
            read.get(5, TimeUnit.SECONDS)
        } finally {
            release.countDown()
            blockedReader.get()?.cancel(true)
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `mutation lease passes the project path resolved before waiting on the publication lock`() {
        val base = createTempDirectory("publication-mutation-canonical-path-")
        val reports = Files.createDirectories(base.resolve("reports"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reports, input).use { }
        val sourceTree = Files.createDirectories(reports.resolve("source-tree"))
        val otherProject = Files.createDirectories(base.resolve("other-project"))
        val alias = base.resolve("project-alias")
        Files.createSymbolicLink(alias, sourceTree.toAbsolutePath())
        val heldWorkspace = ReconstructionOutputWorkspace.open(reports, input)
        val executor = Executors.newSingleThreadExecutor()
        val started = java.util.concurrent.CountDownLatch(1)
        val leaseThread = java.util.concurrent.atomic.AtomicReference<Thread?>()
        try {
            val admitted = executor.submit<Path> {
                leaseThread.set(Thread.currentThread())
                started.countDown()
                ReconstructionOutputWorkspace.withProjectMutationLease(alias, { true }) { it }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val waitDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (leaseThread.get()?.state !in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING) &&
                System.nanoTime() < waitDeadline) Thread.yield()
            assertTrue(leaseThread.get()?.state in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING),
                "mutation request did not block on the held publication lease")
            Files.delete(alias)
            Files.createSymbolicLink(alias, otherProject.toAbsolutePath())
            heldWorkspace.close()
            assertEquals(sourceTree.toRealPath(), admitted.get(5, TimeUnit.SECONDS),
                "the operation must use the path resolved before lock acquisition waited")
        } finally {
            heldWorkspace.close()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `mutation lease binds an absent source-tree to the canonical parent before waiting`() {
        val base = createTempDirectory("publication-mutation-missing-tree-alias-")
        val reportsA = Files.createDirectories(base.resolve("reports-a"))
        val reportsB = Files.createDirectories(base.resolve("reports-b"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reportsA, input).use { }
        ReconstructionOutputWorkspace.open(reportsB, input).use { }
        val alias = base.resolve("reports-alias")
        Files.createSymbolicLink(alias, reportsA.toAbsolutePath())
        val requestedProject = alias.resolve("source-tree")
        val heldWorkspace = ReconstructionOutputWorkspace.open(reportsA, input)
        val executor = Executors.newSingleThreadExecutor()
        val started = java.util.concurrent.CountDownLatch(1)
        val leaseThread = java.util.concurrent.atomic.AtomicReference<Thread?>()
        try {
            val admitted = executor.submit<Path> {
                leaseThread.set(Thread.currentThread())
                started.countDown()
                ReconstructionOutputWorkspace.withProjectMutationLease(requestedProject, { true }) { it }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            val waitDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (leaseThread.get()?.state !in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING) &&
                System.nanoTime() < waitDeadline) Thread.yield()
            assertTrue(leaseThread.get()?.state in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING),
                "mutation request did not block on the canonical parent's publication lease")
            Files.delete(alias)
            Files.createSymbolicLink(alias, reportsB.toAbsolutePath())
            heldWorkspace.close()
            assertEquals(reportsA.resolve("source-tree"), admitted.get(5, TimeUnit.SECONDS),
                "an absent source-tree must remain bound to its canonical parent across lock wait")
        } finally {
            heldWorkspace.close()
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test
    fun `repair marker remains until an operation explicitly verifies recovery`() {
        val base = createTempDirectory("publication-repair-recovery-marker-")
        val reports = Files.createDirectories(base.resolve("reports"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reports, input).use { }
        val sourceTree = Files.createDirectories(reports.resolve("source-tree"))

        assertFailsWith<IllegalStateException> {
            ReconstructionOutputWorkspace.withProjectMutationLease(sourceTree, { true }) {
                throw IllegalStateException("interrupted repair fixture")
            }
        }
        assertTrue(reports.resolve(".reconstruction-repair-in-progress").isRegularFile())
        assertFailsWith<ReconstructionOutputReadUnavailableException> {
            ReconstructionOutputWorkspace.withReadLease(reports) { Unit }
        }
        assertFailsWith<ReconstructionOutputReadUnavailableException> {
            ReconstructionOutputWorkspace.open(reports, input)
        }

        ReconstructionOutputWorkspace.withProjectMutationLease(sourceTree, { false }) { Unit }
        assertTrue(reports.resolve(".reconstruction-repair-in-progress").exists(),
            "a normal return without verified graph recovery must keep readers fail-closed")
        ReconstructionOutputWorkspace.withProjectMutationLease(sourceTree, { true }) { Unit }
        assertFalse(reports.resolve(".reconstruction-repair-in-progress").exists())
        assertEquals(1, ReconstructionOutputWorkspace.withReadLease(reports) { 1 })
    }

    @Test
    fun `abandoned atomic repair marker staging is unavailable to readers and recoverable by a writer`() {
        val base = createTempDirectory("publication-repair-marker-stage-")
        val reports = Files.createDirectories(base.resolve("reports"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reports, input).use { }
        val sourceTree = Files.createDirectories(reports.resolve("source-tree"))
        val stagedMarker = reports.resolve(".reconstruction-repair-in-progress.00000000-0000-0000-0000-000000000001.tmp")
        Files.writeString(stagedMarker, "repair-mutation-v1\n")
        Files.setPosixFilePermissions(stagedMarker, setOf(
            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
        ))
        assertFailsWith<ReconstructionOutputReadUnavailableException> {
            ReconstructionOutputWorkspace.withReadLease(reports) { Unit }
        }

        ReconstructionOutputWorkspace.withProjectMutationLease(sourceTree, { true }) { Unit }
        assertFalse(Files.exists(stagedMarker))
        assertFalse(Files.exists(reports.resolve(".reconstruction-repair-in-progress")))
        assertEquals(1, ReconstructionOutputWorkspace.withReadLease(reports) { 1 })
    }

    @Test
    fun `workspace activation safely removes marker staging left before repair began`() {
        val base = createTempDirectory("publication-repair-marker-activation-")
        val reports = Files.createDirectories(base.resolve("reports"))
        val input = base.resolve("input").apply { writeText("input") }
        ReconstructionOutputWorkspace.open(reports, input).use { }
        val stagedMarker = reports.resolve(".reconstruction-repair-in-progress.00000000-0000-0000-0000-000000000002.tmp")
        Files.writeString(stagedMarker, "partial marker write")
        Files.setPosixFilePermissions(stagedMarker, setOf(
            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
        ))

        ReconstructionOutputWorkspace.open(reports, input).use { }

        assertFalse(Files.exists(stagedMarker))
        assertEquals(1, ReconstructionOutputWorkspace.withReadLease(reports) { 1 })
    }

    @Test
    fun `deferred workspace cleanup releases the process gate from its retirement thread`() {
        val base = createTempDirectory("input-cross-thread-retirement-")
        val input = base.resolve("input").apply { writeText("input") }
        val root = base.resolve("output")
        val workspace = ReconstructionOutputWorkspace.open(root, input)
        val cleanup = Executors.newSingleThreadExecutor()
        try {
            cleanup.submit { workspace.close() }.get(5, TimeUnit.SECONDS)
            ReconstructionOutputWorkspace.open(root, input).use { reopened ->
                assertEquals(sha256(input.readBytes()), reopened.inputSha256)
            }
        } finally {
            cleanup.shutdownNow()
            assertTrue(cleanup.awaitTermination(5, TimeUnit.SECONDS))
            runCatching { workspace.close() }
        }
    }

    @Test
    fun `legacy umask-created lock files remain readable without mutation and writers normalize them`() {
        val base = createTempDirectory("input-legacy-lock-mode-")
        val input = base.resolve("input").apply { writeText("input") }
        val readableRoot = base.resolve("readable")
        ReconstructionOutputWorkspace.open(readableRoot, input).use { }
        val readLock = readableRoot.resolve(".reconstruction.lock")
        Files.setPosixFilePermissions(readLock, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"))

        ReconstructionOutputWorkspace.withReadLease(readableRoot) { assertTrue(readLock.exists()) }
        assertEquals(setOf("OWNER_READ", "OWNER_WRITE", "GROUP_READ", "OTHERS_READ"),
            Files.getPosixFilePermissions(readLock).map { it.name }.toSet())

        val writableRoot = base.resolve("writable")
        ReconstructionOutputWorkspace.open(writableRoot, input).use { }
        val writeLock = writableRoot.resolve(".reconstruction.lock")
        Files.setPosixFilePermissions(writeLock, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"))
        ReconstructionOutputWorkspace.open(writableRoot, input).use { }
        assertEquals(setOf("OWNER_READ", "OWNER_WRITE"), Files.getPosixFilePermissions(writeLock).map { it.name }.toSet())
    }

    @Test
    fun `different binaries preserve active results and switch back to original receipt paths`() {
        val base = createTempDirectory("input-workspaces-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        ReconstructionOutputWorkspace.open(root, a).use {
            root.resolve("analysis").createDirectory().resolve("marker").writeText("analysis-a")
            root.resolve("source-tree").createDirectory().resolve("marker").writeText("source-a")
            root.resolve("source-tree.zip").writeText("archive-a")
            root.resolve(ModuleObservedBehavior.FILE_NAME).writeText("observations-a")
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("source-tree").exists())
            assertFalse(root.resolve(ModuleObservedBehavior.FILE_NAME).exists())
            root.resolve("source-tree").createDirectory().resolve("marker").writeText("source-b")
            root.resolve("source-tree.zip").writeText("archive-b")
            root.resolve(ModuleObservedBehavior.FILE_NAME).writeText("observations-b")
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("analysis-a", root.resolve("analysis/marker").readText())
            assertEquals("source-a", root.resolve("source-tree/marker").readText())
            assertEquals("archive-a", root.resolve("source-tree.zip").readText())
            assertEquals("observations-a", root.resolve(ModuleObservedBehavior.FILE_NAME).readText())
            assertEquals("archive-b", root.resolve("input-cache/${sha256(b.readBytes())}/source-tree.zip").readText())
            assertEquals("observations-b", root.resolve("input-cache/${sha256(b.readBytes())}/${ModuleObservedBehavior.FILE_NAME}").readText())
        }
    }

    @Test
    fun `cache and per-input parent entries are synced before moving active results`() {
        for (failedSync in 0..3) {
            val base = createTempDirectory("input-cache-parent-sync-")
            val root = base.resolve("output")
            val a = base.resolve("a").apply { writeText("input-a") }
            val b = base.resolve("b").apply { writeText("input-b") }
            ReconstructionOutputWorkspace.open(root, a).use {
                root.resolve("source-tree.zip").writeText("accepted-a")
            }

            val synced = mutableListOf<Path>()
            assertFailsWith<IOException> {
                ReconstructionOutputWorkspace.openWithParentSyncForTest(root, b) { parent ->
                    synced.add(parent)
                    if (synced.lastIndex == failedSync) throw IOException("injected parent sync failure")
                    FileChannel.open(parent, READ).use { it.force(true) }
                }
            }

            val cache = root.resolve(ReconstructionOutputWorkspace.CACHE)
            assertEquals(listOf(root, cache, root, cache).take(failedSync + 1), synced)
            assertEquals("accepted-a", root.resolve("source-tree.zip").readText())
            assertFalse(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
            assertEquals(sha256(a.readBytes()),
                Json.parseToJsonElement(root.resolve(ReconstructionOutputWorkspace.ACTIVE).readText())
                    .jsonObject.getValue("inputSha256").jsonPrimitive.content)

            // The failed sync may have left created directories in place. A retry must sync
            // their parents again before archiving the accepted active result.
            ReconstructionOutputWorkspace.open(root, b).use {
                assertFalse(root.resolve("source-tree.zip").exists())
                assertEquals("accepted-a", root.resolve("input-cache/${sha256(a.readBytes())}/source-tree.zip").readText())
            }
        }
    }

    @Test
    fun `existing input-bound output is migrated without dropping its checkpoint state`() {
        val root = createTempDirectory("input-migration-")
        val a = root.resolveSibling(root.fileName.toString() + "-input").apply { writeText("a") }
        root.resolve("analysis/reports").createDirectories().resolve("program_model.json")
            .writeText("{\"inputSha256\":\"${sha256(a.readBytes())}\"}")
        root.resolve("source-tree").createDirectory().resolve("receipt").writeText("kept")
        ReconstructionOutputWorkspace.open(root, a).use { assertEquals("kept", root.resolve("source-tree/receipt").readText()) }
        assertTrue(root.resolve(ReconstructionOutputWorkspace.ACTIVE).exists())
        assertFalse(root.resolve(ReconstructionOutputWorkspace.CACHE).exists())
    }

    @Test
    fun `module observation identity routes the initial handoff to its input`() {
        val base = createTempDirectory("input-observation-identity-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        ModuleObservedBehavior.write(root, aHash, emptyList())

        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve(ModuleObservedBehavior.FILE_NAME).exists())
            assertTrue(root.resolve("input-cache/$aHash/${ModuleObservedBehavior.FILE_NAME}").exists())
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals(aHash, ModuleObservedBehavior.parse(root.resolve(ModuleObservedBehavior.FILE_NAME).readText()).inputSha256)
        }
    }

    @Test
    fun `unscoped initial exploration is bound to first activated input and isolated on switch`() {
        val base = createTempDirectory("input-unscoped-exploration-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        root.resolve("exploration.json").apply { parent.createDirectories(); writeText("exploration-a") }
        root.resolve("agent-progress.json").writeText("progress-a")
        root.resolve("run-history/a/events.jsonl").apply { parent.createDirectories(); writeText("history-a") }

        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("exploration-a", root.resolve("exploration.json").readText())
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("exploration.json").exists())
            assertFalse(root.resolve("agent-progress.json").exists())
            assertFalse(root.resolve("run-history").exists())
            assertEquals("exploration-a", root.resolve("input-cache/$aHash/exploration.json").readText())
            assertEquals("progress-a", root.resolve("input-cache/$aHash/agent-progress.json").readText())
            assertEquals("history-a", root.resolve("input-cache/$aHash/run-history/a/events.jsonl").readText())
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("exploration-a", root.resolve("exploration.json").readText())
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
        }
    }

    @Test
    fun `progress snapshot and full run history follow the selected input`() {
        val base = createTempDirectory("input-history-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("input-a") }
        val b = base.resolve("b").apply { writeText("input-b") }
        val aHash = sha256(a.readBytes())
        val bHash = sha256(b.readBytes())
        ReconstructionOutputWorkspace.open(root, a).use {
            root.resolve("agent-progress.json").writeText("progress-a")
            root.resolve("run-history/a").createDirectories().resolve("events.jsonl").writeText("history-a")
            root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).createDirectory().resolve("parse.json").writeText("feedback-a")
        }
        ReconstructionOutputWorkspace.open(root, b).use {
            assertFalse(root.resolve("agent-progress.json").exists())
            assertFalse(root.resolve("run-history").exists())
            assertFalse(root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).exists())
            root.resolve("agent-progress.json").writeText("progress-b")
            root.resolve("run-history/b").createDirectories().resolve("events.jsonl").writeText("history-b")
            root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).createDirectory().resolve("parse.json").writeText("feedback-b")
        }
        ReconstructionOutputWorkspace.open(root, a).use {
            assertEquals("progress-a", root.resolve("agent-progress.json").readText())
            assertEquals("history-a", root.resolve("run-history/a/events.jsonl").readText())
            assertEquals("feedback-a", root.resolve("${ModuleCompilerFeedbackStore.DIRECTORY}/parse.json").readText())
            assertEquals("progress-b", root.resolve("input-cache/$bHash/agent-progress.json").readText())
            assertEquals("history-b", root.resolve("input-cache/$bHash/run-history/b/events.jsonl").readText())
            assertEquals("feedback-b", root.resolve("input-cache/$bHash/${ModuleCompilerFeedbackStore.DIRECTORY}/parse.json").readText())
            assertEquals(aHash, it.inputSha256)
        }
    }

    @Test
    fun `exclusive leases reject concurrent writers and can be reacquired after close`() {
        val base = createTempDirectory("input-lease-")
        val input = base.resolve("input").apply { writeText("a") }
        val root = base.resolve("output")
        ReconstructionOutputWorkspace.open(root, input).use {
            assertFailsWith<ReconstructionOutputBusyException> { ReconstructionOutputWorkspace.open(root, input) }
        }
        ReconstructionOutputWorkspace.open(root, input).close()
    }

    @Test
    fun `publication ownership validates lock lifetime and canonical directory identity`() {
        val base = createTempDirectory("input-publication-ownership-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("a") }
        val workspace = ReconstructionOutputWorkspace.open(root, input)
        workspace.publicationLock.validate()
        assertSame(workspace.publicationLock, workspace.publicationLock.borrow(root, workspace.inputSha256))
        assertFailsWith<IllegalArgumentException> {
            workspace.publicationLock.borrow(base.resolve("other"), workspace.inputSha256)
        }
        assertFailsWith<IllegalArgumentException> {
            workspace.publicationLock.borrow(root, "0".repeat(64))
        }

        val displaced = base.resolve("displaced-output")
        Files.move(root, displaced, ATOMIC_MOVE)
        Files.createDirectory(root)
        assertFailsWith<IllegalStateException> { workspace.publicationLock.validate() }
        workspace.close()
        assertFailsWith<IllegalStateException> { workspace.publicationLock.validate() }
    }

    @Test
    fun `publication borrowing refuses input bytes changed after workspace admission`() {
        val base = createTempDirectory("input-publication-input-change-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("before") }
        ReconstructionOutputWorkspace.open(root, input).use { workspace ->
            input.writeText("after")
            assertFailsWith<IllegalStateException> {
                workspace.publicationLock.borrow(root, workspace.inputSha256)
            }
        }
    }

    @Test
    fun `publication borrowing tolerates access-time-only changes while rechecking content identity`() {
        val base = createTempDirectory("input-publication-atime-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("unchanged input") }
        ReconstructionOutputWorkspace.open(root, input).use { workspace ->
            Files.setAttribute(input, "basic:lastAccessTime", java.nio.file.attribute.FileTime.fromMillis(1))
            assertSame(workspace.publicationLock, workspace.publicationLock.borrow(root, workspace.inputSha256))
            assertEquals(sha256(input.readBytes()), workspace.inputSha256)
        }
    }

    @Test
    fun `closed publication ownership cannot be reused`() {
        val base = createTempDirectory("input-publication-closed-")
        val workspace = ReconstructionOutputWorkspace.open(
            base.resolve("output"), base.resolve("input").apply { writeText("a") },
        )
        val ownership = workspace.publicationLock
        workspace.close()
        assertFailsWith<IllegalStateException> { ownership.validate() }
    }

    @Test
    fun `pending publication journal blocks activation before input recovery moves entries`() {
        val base = createTempDirectory("input-publication-pending-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("a") }
        val b = base.resolve("b").apply { writeText("b") }
        val from = sha256(a.readBytes())
        val to = sha256(b.readBytes())
        ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
        val incoming = root.resolve("input-cache/$to").createDirectories()
        incoming.resolve("source-tree.zip").writeText("b")
        root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(transaction(from, to, "archive").toString())
        root.resolve(ReconstructionOutputWorkspace.PUBLICATION).writeText("pending")

        assertFails { ReconstructionOutputWorkspace.open(root, b) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
        assertEquals("b", incoming.resolve("source-tree.zip").readText())
        assertTrue(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
    }

    @Test
    fun `workspace activation recovers a decided publication before input routing`() {
        val base = createTempDirectory("input-publication-recover-")
        val root = base.resolve("output")
        val input = base.resolve("input").apply { writeText("input") }
        val inputHash = sha256(input.readBytes())
        ReconstructionOutputWorkspace.open(root, input).use {
            root.resolve("source-tree.zip").writeText("old")
        }
        root.resolve(ReconstructionOutputWorkspace.ACTIVE).writeText(
            "{\"schemaVersion\":1,\"inputSha256\":\"$inputHash\"}",
        )
        var rootSyncs = 0
        val publication = ReconstructionOutputWorkspace.openWithParentSyncForTest(root, input) { directory ->
            if (directory == root && ++rootSyncs == 5) throw IOException("decision directory sync")
            FileChannel.open(directory, READ).use { it.force(true) }
        }.use { workspace ->
            workspace.publish(setOf("source-tree.zip"), { it.resolve("source-tree.zip").writeText("new") })
        }
        assertEquals(PublicationResult.PENDING, publication)

        ReconstructionOutputWorkspace.open(root, input).use {
            assertEquals("new", root.resolve("source-tree.zip").readText())
            assertFalse(root.resolve(ReconstructionOutputWorkspace.PUBLICATION).exists())
        }
    }

    @Test
    fun `interrupted archive and restore phases resume without replacing preserved entries`() {
        for (phase in listOf("archive", "restore")) {
            val base = createTempDirectory("input-switch-recovery-")
            val root = base.resolve("output")
            val a = base.resolve("a").apply { writeText("a") }
            val b = base.resolve("b").apply { writeText("b") }
            val from = sha256(a.readBytes()); val to = sha256(b.readBytes())
            ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
            val outgoing = root.resolve("input-cache/$from").createDirectories()
            val incoming = root.resolve("input-cache/$to").createDirectories()
            incoming.resolve("source-tree.zip").writeText("b")
            Files.move(root.resolve("source-tree.zip"), outgoing.resolve("source-tree.zip"), ATOMIC_MOVE)
            if (phase == "restore") Files.move(incoming.resolve("source-tree.zip"), root.resolve("source-tree.zip"), ATOMIC_MOVE)
            root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(transaction(from, to, phase).toString())
            ReconstructionOutputWorkspace.open(root, b).use {
                assertEquals("b", root.resolve("source-tree.zip").readText())
                assertEquals("a", outgoing.resolve("source-tree.zip").readText())
                assertFalse(root.resolve(ReconstructionOutputWorkspace.SWITCH).exists())
            }
        }
    }

    @Test
    fun `malformed switch records and links cannot move or overwrite existing results`() {
        val base = createTempDirectory("input-switch-invalid-")
        val root = base.resolve("output")
        val a = base.resolve("a").apply { writeText("a") }
        val b = base.resolve("b").apply { writeText("b") }
        ReconstructionOutputWorkspace.open(root, a).use { root.resolve("source-tree.zip").writeText("a") }
        val bad = JsonObject(transaction(sha256(a.readBytes()), sha256(b.readBytes()), "archive") +
            ("restoreEntries" to JsonArray(listOf(JsonPrimitive("../outside")))))
        root.resolve(ReconstructionOutputWorkspace.SWITCH).writeText(bad.toString())
        assertFailsWith<IllegalArgumentException> { ReconstructionOutputWorkspace.open(root, b) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
        Files.delete(root.resolve(ReconstructionOutputWorkspace.SWITCH))
        Files.createSymbolicLink(root.resolve("source-tree"), base.resolve("outside"))
        assertFailsWith<IllegalArgumentException> { ReconstructionOutputWorkspace.open(root, a) }
        assertEquals("a", root.resolve("source-tree.zip").readText())
    }

    private fun transaction(from: String, to: String, phase: String) = buildJsonObject {
        put("schemaVersion", 1); put("from", from); put("to", to); put("phase", phase)
        put("archiveEntries", JsonArray(listOf(JsonPrimitive("source-tree.zip"))))
        put("restoreEntries", JsonArray(listOf(JsonPrimitive("source-tree.zip"))))
    }
}
