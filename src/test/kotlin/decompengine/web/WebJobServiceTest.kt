package decompengine.web

import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import org.junit.jupiter.api.extension.ExtendWith
import decompengine.jobs.JobStore
import decompengine.jobs.AtomicUploadPublisher
import decompengine.jobs.JobStoreDirectories
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowStoreException
import decompengine.jobs.forceJobStoreDirectory
import decompengine.jobs.prepareJobStoreDirectories
import decompengine.jobs.elfFixture
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

@ExtendWith(RecoveryMatrixEvidence::class)
class WebJobServiceTest {
    @Test fun `startup durability refusal preserves its public type and the full private recovery context`() {
        val original = UnsupportedOperationException("PRIVATE directory provider")
        val maintenance = WebJobServiceException("STORE_DURABILITY_UNAVAILABLE", "PRIVATE directory failure", original)
        val recovery = WorkflowStoreException("STARTUP_RECOVERY_INCOMPLETE", "PRIVATE recovery context", true, maintenance)
        val reported = assertIs<WebJobServiceException>(webStartupFailure(recovery))
        assertEquals(maintenance.code, reported.code)
        assertEquals(publicWebDiagnosticMessage(reported.code), reported.message)
        assertFalse(reported.message!!.contains("PRIVATE"))
        kotlin.test.assertSame(recovery, reported.cause)
        kotlin.test.assertSame(maintenance, recovery.cause)
        kotlin.test.assertSame(original, maintenance.cause)
        assertTrue(recovery.outcomeUnknown)
        assertTrue(original.suppressed.isEmpty())
        assertTrue(maintenance.suppressed.isEmpty())
        assertTrue(recovery.suppressed.isEmpty())
        for (failure in listOf(original, maintenance,
            WorkflowStoreException("RECOVERY_CANCELLED", "Cancelled", true, maintenance),
            WorkflowStoreException("STARTUP_RECOVERY_INCOMPLETE", "Incomplete", true, original))) {
            kotlin.test.assertSame(failure, webStartupFailure(failure))
        }
    }

    @Test fun `API library admits ten thousand sorted identities and counts unrelated entries independently`() {
        val ids = (1..10_000).map { it.toString(16).padStart(32, '0') }
        val unrelated = (1..512).map { "retained-$it" }
        assertEquals(ids, collectWebJobLibraryIds((ids.reversed() + unrelated).asSequence(), {}))
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            collectWebJobLibraryIds((ids + "f".repeat(32)).asSequence(), {})
        }.code)
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            collectWebJobLibraryIds((ids + unrelated + "another-entry").asSequence(), {})
        }.code)
        for ((entries, jobs) in listOf(0 to 1, 10_513 to 1, 2 to 0, 10_512 to 10_001, 1 to 2)) {
            assertFailsWith<IllegalArgumentException> { WebJobLibraryEntryLimits(entries, jobs) }
        }
    }

    @Test fun `API root admission refuses late enumeration failures and counts names that are not jobs`() {
        var returned: List<String>? = null
        val original = java.io.IOException("PRIVATE root enumeration details")
        val failure = assertFailsWith<WebJobServiceException> {
            returned = collectWebJobLibraryIds(sequence { yield("a".repeat(32)); throw original }, {})
        }
        assertEquals("JOB_STORAGE_UNAVAILABLE", failure.code)
        kotlin.test.assertSame(original, failure.cause)
        assertFalse(failure.message!!.contains("PRIVATE"))
        assertEquals(null, returned)
        assertTrue(original.suppressed.isEmpty())
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            collectWebJobLibraryIds(sequenceOf("unknown-a", "unknown-b", "a".repeat(32)), {},
                WebJobLibraryEntryLimits(2, 2))
        }.code)
    }

    @Test fun `collection deadline keeps its exact boundary wrap arithmetic and sticky expiry`() {
        var clock = 5_000_000_000L
        val deadline = WebJobCollectionDeadline(0) { clock }
        deadline.checkpoint()
        clock++
        val failure = assertFailsWith<WebAccessDenied> { deadline.checkpoint() }
        assertEquals(503, failure.status)
        assertEquals("LISTING_LIMIT", failure.code)
        clock = 0
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> { deadline.checkpoint() }.code)
        clock = Long.MIN_VALUE + 1_000_000_000L
        val wrapped = WebJobCollectionDeadline(Long.MAX_VALUE - 2_000_000_000L) { clock }
        wrapped.checkpoint()
        clock = Long.MIN_VALUE + 4_000_000_000L
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> { wrapped.checkpoint() }.code)
    }

    @Test fun `empty root and a reader returning after deadline cannot publish a successful collection`() {
        var clock = 0L
        val deadline = WebJobCollectionDeadline(0) { clock }
        var ids: List<String>? = null
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> {
            ids = collectWebJobLibraryIds(sequence { yield("unknown-entry"); clock = 6_000_000_000L }, deadline::checkpoint)
        }.code)
        assertEquals(null, ids)
        clock = 0
        val readDeadline = WebJobCollectionDeadline(0) { clock }
        val budget = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        var returned: ByteArray? = null
        var reads = 0
        assertEquals("LISTING_LIMIT", assertFailsWith<WebAccessDenied> {
            returned = readWebJobCollectionMetadata(budget, 8, readDeadline::checkpoint) { _, _ ->
                reads++; clock = 6_000_000_000L; ByteArray(1)
            }
        }.code)
        assertEquals(null, returned)
        assertEquals(1, reads)
        assertEquals(1L, budget.readBytes)
    }

    @Test fun `collection metadata shares its byte budget and preserves expiry through per-record catches`() {
        var clock = 0L
        var reads = 0
        val deadline = WebJobCollectionDeadline(0) { clock }
        val interrupted = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        val expired = assertFailsWith<WebAccessDenied> {
            readWebJobCollectionMetadata(interrupted, 8, deadline::checkpoint) { _, check ->
                reads++; clock = 6_000_000_000L; check(); error("expired callback cannot return bytes")
            }
        }
        assertEquals(503, expired.status)
        assertEquals("LISTING_LIMIT", expired.code)
        clock = 0
        assertFailsWith<WebAccessDenied> {
            readWebJobCollectionMetadata(interrupted, 8, deadline::checkpoint) { _, _ -> reads++; ByteArray(1) }
        }
        assertEquals(1, reads)

        val bounded = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        val allowances = mutableListOf<Long>()
        repeat(2) {
            readWebJobCollectionMetadata(bounded, 8, {}) { allowance, check ->
                allowances += allowance; check(); ByteArray(4)
            }
        }
        assertEquals(listOf(8L, 4L), allowances)
        assertEquals(8L, bounded.readBytes)
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            readWebJobCollectionMetadata(bounded, 8, {}) { _, _ -> error("exhausted bytes cannot start a reader") }
        }.code)
        val incomplete = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        val original = java.io.IOException("PRIVATE physical failure")
        val failed = assertFailsWith<WebJobServiceException> {
            readWebJobCollectionMetadata(incomplete, 8, {}) { _, _ -> throw original }
        }
        kotlin.test.assertSame(original, failed.cause)
        assertFalse(failed.message!!.contains("PRIVATE"))
        assertEquals("JOB_STORAGE_UNAVAILABLE", assertFailsWith<WebJobServiceException> {
            readWebJobCollectionMetadata(incomplete, 8, {}) { _, _ -> error("failed physical reads cannot resume") }
        }.code)
    }

    @Test fun `SPA startup admits the existing ten thousand job library without relaxing legacy or byte profiles`() {
        val legacy = startupRecoveryLimitsForWeb(WebUiMode.LEGACY)
        val library = startupRecoveryLimitsForWeb(WebUiMode.SPA)
        assertEquals(decompengine.jobs.WorkflowStartupRecoveryLimits(), legacy)
        assertEquals(4096, legacy.maximumEntries)
        assertEquals(decompengine.jobs.WorkflowStartupRecoveryProfile.WEB_LIBRARY, library.profile)
        assertEquals(10_512, library.maximumEntries)
        assertEquals(10_000, library.profile.maximumJobs)
        assertEquals(legacy.maximumReadBytes, library.maximumReadBytes)
        assertEquals(legacy.maximumPlanBytes, library.maximumPlanBytes)
        assertFailsWith<IllegalArgumentException> { decompengine.jobs.WorkflowStartupRecoveryLimits(maximumEntries = 4097) }
        val ids = (1..10_000).map { it.toString(16).padStart(32, '0') }
        val prepared = mutableListOf<String>()
        var maintenance = 0
        val admitted = decompengine.jobs.WorkflowStartupRecoveryBudget(library)
        decompengine.jobs.executeWorkflowStartupRecovery((ids.reversed() + listOf("root-lock", "staging")).asSequence(), admitted,
            prepare = { prepared += it; null }, beforeChanges = { maintenance++ })
        assertEquals(ids, prepared)
        assertEquals(10_002, admitted.entries)
        assertEquals(10_000, admitted.jobs)
        assertEquals(0L, admitted.readBytes)
        assertEquals(0L, admitted.planBytes)
        assertEquals(1, maintenance)
        for ((limits, names) in listOf(legacy to ids.take(4097), library to (ids + "f".repeat(32)),
            library to (1..10_513).map { "unknown-$it" })) {
            val refused = decompengine.jobs.WorkflowStartupRecoveryBudget(limits)
            assertEquals("STORE_LIMIT", assertFailsWith<WorkflowStoreException> {
                decompengine.jobs.executeWorkflowStartupRecovery(names.asSequence(), refused,
                    prepare = { error("complete admission precedes metadata reads") },
                    beforeChanges = { error("refused admission cannot begin maintenance") })
            }.code)
            assertFalse(refused.changesStarted)
        }
    }

    @Test fun `dashboard enumerates every root entry before reading and retains compact ordered rows`() {
        val a = "a".repeat(32); val b = "b".repeat(32); val c = "c".repeat(32)
        val events = mutableListOf<String>()
        val names = listOf(b, "retained-layout", a, c)
        val root = sequence { for (name in names) { events += "root-$name"; yield(name) } }
        val budget = WebDashboardReadBudget(WebDashboardReadLimits(4, 64, 4096))
        val first = dashboardFixtureJob(a)
        val second = dashboardFixtureJob(b, createdAt = "2026-10-20T00:00:01Z")
        val rows = collectWebDashboardRows(root, budget) { id ->
            assertEquals(names.map { "root-$it" }, events.take(4))
            events += "inspect-$id"
            budget.read(64) { _, check -> check(); ByteArray(3) }
            if (id == c) WebJobInspection.Unavailable(WebJobDiagnostic(c, "CORRUPT_LEGACY_JOB", "Retained record is unavailable."))
            else {
                budget.read(64) { _, check -> check(); ByteArray(2) }
                val job = if (id == a) first else second
                val snapshot = decompengine.jobs.WorkflowJobSnapshot(id, "version_fixture",
                    decompengine.jobs.LegacyWorkflowObservation("ab".repeat(32), "uploaded", false), emptyList(), null)
                dashboardFixtureRow(job, snapshot)
            }
        }
        assertEquals(listOf("inspect-$a", "inspect-$b", "inspect-$c"), events.drop(4))
        assertEquals(listOf(b, a), rows.jobs.map { it.id })
        kotlin.test.assertSame(second, rows.jobs.first())
        kotlin.test.assertSame(first, rows.jobs.last())
        assertEquals(listOf(c), rows.unavailable.map { it.jobId })
        assertEquals(4, budget.entries)
        assertEquals(13L, budget.readBytes)
        assertEquals(3, budget.retainedRows)
    }

    @Test fun `dashboard unknown-entry exhaustion and late enumeration failure cannot read a partial listing`() {
        var inspections = 0
        val exhausted = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        val failure = assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequenceOf("unknown-a", "unknown-b", "unknown-c"), exhausted) {
                inspections++; error("root admission must finish before inspection")
            }
        }
        assertEquals("STORE_LIMIT", failure.code)
        assertEquals(2, exhausted.entries)
        val original = java.io.IOException("PRIVATE enumeration details")
        val incomplete = assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequence { yield("a".repeat(32)); throw original }, WebDashboardReadBudget()) {
                inspections++; error("incomplete enumeration cannot inspect known rows")
            }
        }
        assertEquals("JOB_STORAGE_UNAVAILABLE", incomplete.code)
        kotlin.test.assertSame(original, incomplete.cause)
        assertFalse(incomplete.message!!.contains("PRIVATE"))
        assertEquals(0, inspections)
        assertTrue(original.suppressed.isEmpty())
    }

    @Test fun `dashboard exact byte allowance and incomplete physical reads latch refusal before another read`() {
        val bounded = WebDashboardReadBudget(WebDashboardReadLimits(2, 5, 4096))
        val allowances = mutableListOf<Long>()
        for (size in listOf(3, 2)) bounded.read(64) { allowance, check ->
            allowances += allowance; check(); ByteArray(size)
        }
        val exhausted = assertFailsWith<WebJobServiceException> {
            bounded.read(64) { _, _ -> error("an exhausted allowance cannot perform another physical read") }
        }
        assertEquals("STORE_LIMIT", exhausted.code)
        assertEquals(listOf(5L, 2L), allowances)
        assertEquals(5L, bounded.readBytes)
        assertFailsWith<WebJobServiceException> { bounded.read(64) { _, _ -> error("a refused budget cannot read again") } }

        val incomplete = WebDashboardReadBudget(WebDashboardReadLimits(2, 8, 4096))
        val original = java.io.IOException("PRIVATE failure after physical bytes were read")
        var inspections = 0
        var physicalAllowance = 0L
        val failed = assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequenceOf("a".repeat(32), "b".repeat(32)), incomplete) { id ->
                inspections++
                try {
                    incomplete.read(64) { allowance, _ -> physicalAllowance += allowance; throw original }
                } catch (_: WebJobServiceException) { /* Model the ordinary per-record diagnostic catch. */ }
                WebJobInspection.Unavailable(WebJobDiagnostic(id, "JOB_RECORD_UNAVAILABLE", "Retained record is unavailable."))
            }
        }
        assertEquals("JOB_STORAGE_UNAVAILABLE", failed.code)
        kotlin.test.assertSame(original, failed.cause)
        assertEquals(8L, physicalAllowance)
        assertEquals(1, inspections)
        assertEquals(0, incomplete.retainedRows)
        assertTrue(original.suppressed.isEmpty())
    }

    @Test fun `dashboard charges both workflow inspection and legacy presentation before returning any rows`() {
        val budget = WebDashboardReadBudget(WebDashboardReadLimits(2, 15, 4096))
        var reads = 0
        var completed = 0
        var returned: WebDashboardRows? = null
        val failure = assertFailsWith<WebJobServiceException> {
            returned = collectWebDashboardRows(sequenceOf("a".repeat(32), "b".repeat(32)), budget) { id ->
                repeat(2) {
                    budget.read(64) { allowance, _ ->
                        reads++
                        if (allowance < 4) throw decompengine.repair.RepairBudgetExceededException("PRIVATE oversized metadata")
                        ByteArray(4)
                    }
                }
                completed++
                dashboardFixtureRow(dashboardFixtureJob(id))
            }
        }
        assertEquals("STORE_LIMIT", failure.code)
        assertFalse(failure.message!!.contains("PRIVATE"))
        assertEquals(4, reads)
        assertEquals(1, completed)
        assertEquals(12L, budget.readBytes)
        assertEquals(1, budget.retainedRows)
        assertEquals(null, returned)
    }

    @Test fun `dashboard retention accounts full UTF16 fields and refuses instead of truncating rows`() {
        val id = "a".repeat(32)
        val job = dashboardFixtureJob(id, statusMessage = "\ud83d\ude00".repeat(30))
        val exact = WebDashboardReadBudget(WebDashboardReadLimits(1, 8, 234))
        val rows = collectWebDashboardRows(sequenceOf(id), exact) { dashboardFixtureRow(job) }
        // id32 + filename9 + status8 + two timestamps40 + message60 + path50 + ELF category strings35.
        assertEquals(234L, exact.retainedTextUnits)
        kotlin.test.assertSame(job, rows.jobs.single())
        assertEquals(60, rows.jobs.single().statusMessage!!.length)
        val short = WebDashboardReadBudget(WebDashboardReadLimits(1, 8, 233))
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequenceOf(id), short) { dashboardFixtureRow(job) }
        }.code)
        assertEquals(0, short.retainedRows)
        assertEquals("STORE_LIMIT", assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequenceOf(id), WebDashboardReadBudget(WebDashboardReadLimits(1, 8, 1))) {
                WebJobInspection.Unavailable(WebJobDiagnostic(id, "JOB_RECORD_UNAVAILABLE", "Retained record is unavailable."))
            }
        }.code)
        assertFailsWith<IllegalArgumentException> { WebDashboardReadLimits(4097) }
        assertFailsWith<IllegalArgumentException> { WebDashboardReadLimits(maximumReadBytes = 64L * 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> { WebDashboardReadLimits(maximumRetainedTextUnits = 16L * 1024 * 1024 + 1) }
    }

    @Test fun `dashboard cancellation before or during the last read cannot return a successful collection`() {
        val id = "a".repeat(32)
        var cancelled = true
        assertEquals("SERVICE_STOPPED", assertFailsWith<WebJobServiceException> {
            collectWebDashboardRows(sequenceOf(id), WebDashboardReadBudget(cancellation = { cancelled })) {
                error("a cancelled listing cannot inspect")
            }
        }.code)
        for (duringRead in listOf(true, false)) {
            cancelled = false
            val budget = WebDashboardReadBudget(cancellation = { cancelled })
            val stopped = assertFailsWith<WebJobServiceException> {
                collectWebDashboardRows(sequenceOf(id), budget) {
                    if (duringRead) budget.read(64) { _, _ -> cancelled = true; ByteArray(1) }
                    cancelled = true
                    dashboardFixtureRow(dashboardFixtureJob(id))
                }
            }
            assertEquals("SERVICE_STOPPED", stopped.code)
            assertEquals(0, budget.retainedRows)
        }
        Thread.currentThread().interrupt()
        try {
            val interrupted = assertFailsWith<WebJobServiceException> { WebDashboardReadBudget().checkpoint() }
            assertEquals("SERVICE_STOPPED", interrupted.code)
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    private fun dashboardFixtureJob(id: String, createdAt: String = "2026-10-20T00:00:00Z", statusMessage: String? = null) =
        decompengine.jobs.Job(id, "fixed.elf", "uploaded", createdAt, statusMessage = statusMessage,
            sizeBytes = 64, binaryPath = Path.of("fixture/$id/input.elf"),
            metadata = decompengine.binary.ElfMetadata("ELF64", "little", 1u, "System V", "executable", "x86-64",
                0uL, 64u, 0u, 0u, 0u))

    private fun dashboardFixtureRow(job: decompengine.jobs.Job, snapshot: decompengine.jobs.WorkflowJobSnapshot? = null) =
        WebJobInspection.Available(WebJobPresentation(job, snapshot, WebReportContext(Path.of("fixture/reports"))))

    @Test fun `terminal publication already admitted completes before shutdown can publish its signal`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val attempted = CountDownLatch(1)
        val committed = java.util.concurrent.atomic.AtomicBoolean(false)
        val stopping = java.util.concurrent.atomic.AtomicBoolean(false)
        val fence = WebCompletionPublicationFence {
            assertTrue(committed.get(), "a shutdown signal cannot overtake an admitted terminal publication")
            stopping.set(true)
        }
        val publication = java.util.concurrent.FutureTask {
            fence.publishCompletion {
                assertFalse(stopping.get())
                entered.countDown()
                check(release.await(45, TimeUnit.SECONDS))
                assertFalse(stopping.get())
                committed.set(true)
            }
        }
        val shutdown = java.util.concurrent.FutureTask { attempted.countDown(); fence.signalShutdown() }
        val publisher = Thread(publication, "pure-terminal-publication-fence").apply { isDaemon = true }
        val stopper = Thread(shutdown, "pure-terminal-shutdown-fence").apply { isDaemon = true }
        try {
            publisher.start()
            assertTrue(entered.await(15, TimeUnit.SECONDS))
            stopper.start()
            assertTrue(attempted.await(15, TimeUnit.SECONDS))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
            val blockedStates = setOf(Thread.State.BLOCKED, Thread.State.WAITING)
            while (stopper.state !in blockedStates &&
                stopper.isAlive && System.nanoTime() < deadline) Thread.yield()
            assertTrue(stopper.state in blockedStates)
            assertFalse(stopping.get())
            assertFalse(shutdown.isDone)
            release.countDown()
            publication.get(15, TimeUnit.SECONDS)
            shutdown.get(15, TimeUnit.SECONDS)
            assertTrue(committed.get())
            assertTrue(stopping.get())
        } finally {
            release.countDown()
            publisher.join(5000)
            stopper.join(5000)
        }
        assertFalse(publisher.isAlive)
        assertFalse(stopper.isAlive)
    }

    @Test fun `shutdown first makes the fenced legacy terminal decision fail without changing prior failures`() {
        var stopping = false
        var writes = 0
        val fence = WebCompletionPublicationFence { stopping = true }
        fence.signalShutdown()
        val selected = fence.publishCompletion {
            selectWebLegacyCompletion("complete", "authored completion", stopping).also { writes++ }
        }
        assertEquals("failed" to "Server stopped before the operation reported completion", selected)
        assertEquals("failed" to "authored failure", selectWebLegacyCompletion("failed", "authored failure", true))
        assertEquals("complete" to "authored completion", selectWebLegacyCompletion("complete", "authored completion", false))
        assertEquals(1, writes)
    }

    @Test fun `terminal publication failure releases its fence without mutating retained failure graphs`() {
        var signalled = false
        val fence = WebCompletionPublicationFence { signalled = true }
        val original = IllegalStateException("authored terminal publication failure").apply {
            addSuppressed(IllegalArgumentException("retained diagnostic"))
        }
        val retained = original.suppressed
        val failure = assertFailsWith<IllegalStateException> { fence.publishCompletion { throw original } }
        kotlin.test.assertSame(original, failure)
        kotlin.test.assertContentEquals(retained, original.suppressed)
        fence.signalShutdown()
        assertTrue(signalled)
    }

    @Test fun `startup hook precedes construction and normal shutdown reaches the published owner`() {
        val events = mutableListOf<String>()
        val owner = Any()
        lateinit var shutdown: () -> Unit
        lateinit var cancelled: () -> Boolean
        val returned = startWebServerLifecycle(registerShutdown = { action ->
            events += "register"
            shutdown = action
            val remove: () -> Unit = { events += "remove" }
            remove
        }, create = { cancellation ->
            events += "construct"
            cancelled = cancellation
            assertFalse(cancellation())
            owner
        }, start = { events += "start" }, stop = { events += "stop" })
        kotlin.test.assertSame(owner, returned)
        assertEquals(listOf("register", "construct", "start"), events)
        shutdown()
        assertTrue(cancelled())
        assertEquals(listOf("register", "construct", "start", "stop"), events)
    }

    @Test fun `shutdown during construction prevents start and cleans only a late published owner`() {
        for (failConstruction in listOf(false, true)) {
            lateinit var shutdown: () -> Unit
            var constructions = 0
            var starts = 0
            var stops = 0
            var removals = 0
            val original = IllegalStateException("authored constructor cancellation")
            val failure = assertFailsWith<IllegalStateException> {
                startWebServerLifecycle(registerShutdown = { action ->
                    shutdown = action
                    val remove: () -> Unit = { removals++ }
                    remove
                }, create = { cancellation ->
                    constructions++
                    shutdown()
                    assertTrue(cancellation())
                    if (failConstruction) throw original
                    Any()
                }, start = { starts++ }, stop = { stops++ })
            }
            if (failConstruction) kotlin.test.assertSame(original, failure)
            else assertEquals("Web server startup cancelled", failure.message)
            assertEquals(1, constructions)
            assertEquals(0, starts)
            assertEquals(if (failConstruction) 0 else 1, stops)
            assertEquals(1, removals)
        }
    }

    @Test fun `startup cleanup failures use fresh bounded wrappers without growing the original failure graph`() {
        val original = IllegalStateException("authored start failure").apply { addSuppressed(IllegalArgumentException("retained")) }
        val retained = original.suppressed
        val removal = IllegalArgumentException("authored hook cleanup failure")
        val stop = IllegalStateException("authored owner cleanup failure")
        var first: Throwable? = null
        repeat(2) {
            var starts = 0
            var stops = 0
            val failure = assertFailsWith<IllegalStateException> {
                startWebServerLifecycle(registerShutdown = {
                    val remove: () -> Unit = { throw removal }
                    remove
                }, create = { Any() }, start = { starts++; throw original }, stop = { stops++; throw stop })
            }
            kotlin.test.assertSame(original, failure.cause)
            kotlin.test.assertContentEquals(arrayOf<Throwable>(removal, stop), failure.suppressed)
            kotlin.test.assertContentEquals(retained, original.suppressed)
            assertEquals(1, starts)
            assertEquals(1, stops)
            if (first != null) assertTrue(first !== failure)
            first = failure
        }
    }

    @Test fun `cancelled or refused hook registration cannot construct a startup owner`() {
        var constructions = 0
        var removals = 0
        val cancelled = assertFailsWith<IllegalStateException> {
            startWebServerLifecycle(registerShutdown = { action ->
                action()
                val remove: () -> Unit = { removals++ }
                remove
            }, create = { constructions++; Any() }, start = { error("cancelled startup must not run") },
                stop = { error("no owner exists to stop") })
        }
        assertEquals("Web server startup cancelled", cancelled.message)
        assertEquals(0, constructions)
        assertEquals(1, removals)
        val original = IllegalStateException("authored registration refusal")
        val refused = assertFailsWith<IllegalStateException> {
            startWebServerLifecycle(registerShutdown = { throw original }, create = { constructions++; Any() },
                start = { error("unregistered startup must not run") }, stop = { error("no owner exists to stop") })
        }
        kotlin.test.assertSame(original, refused)
        assertEquals(0, constructions)
    }

    @Test
    fun `recovery inspection excludes a live multipart stage and resumes after publication`() = withStore { store, root ->
        val boundary = "recovery-overlap"
        val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"active.elf\"\r\n\r\n".toByteArray() +
            elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val callers = Executors.newSingleThreadExecutor()
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            val input = object : java.io.FilterInputStream(body.inputStream()) {
                private fun waitForRelease() {
                    entered.countDown()
                    check(release.await(10, TimeUnit.SECONDS))
                }
                override fun read(): Int { waitForRelease(); return super.read() }
                override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                    waitForRelease()
                    return super.read(bytes, offset, length)
                }
            }
            try {
                val uploaded = callers.submit<decompengine.jobs.Job> {
                    input.use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
                }
                assertTrue(entered.await(10, TimeUnit.SECONDS))
                val stage = Files.newDirectoryStream(root, ".upload-stream-v1-*").use { it.toList().single() }
                val before = Files.readAllBytes(stage.resolve("input.elf"))
                assertEquals(1, store.recoveryInventory().retainedUploadStages)
                val failure = assertFailsWith<WebJobServiceException> { service.recoveryInventory() }
                assertEquals("RECOVERY_INSPECTION_BUSY", failure.code)
                assertEquals(failure.code, publicWebDiagnosticCode(failure.code))
                assertEquals("Recovery inspection is paused while uploads are in progress. Refresh after uploads finish.",
                    publicWebDiagnosticMessage(failure.code))
                kotlin.test.assertContentEquals(before, Files.readAllBytes(stage.resolve("input.elf")))
                assertTrue(Files.isDirectory(stage))
                release.countDown()
                val job = uploaded.get(10, TimeUnit.SECONDS)
                assertEquals(job.id, service.get(job.id).id)
                assertFalse(Files.exists(stage))
                val settled = service.recoveryInventory()
                assertTrue(settled.inventoryComplete)
                assertEquals(0, settled.retainedUploadStages)
                assertEquals(0, settled.retainedMetadataFiles)
                assertEquals(0L, settled.observedBytes)
            } finally {
                release.countDown()
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(10, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun `scheduler reads preserve absent storage and distinguish shutdown and unknown executor metrics`() = withStore { _, root ->
        val absent = root.resolve("absent")
        lateinit var ownedService: WebJobService
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            ownedService = service
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            assertFailsWith<WebJobServiceException> { service.schedulerSnapshot() }
            service.initializeExistingStorage()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            val sample = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
            assertEquals(0, sample.activeWorkers)
            assertEquals(0, sample.queuedTasks)
            assertEquals(2, sample.workerLimit)
            assertEquals(32, sample.queueCapacity)
            service.beginShutdown()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            assertTrue(assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot()).stopping)
            assertFalse(Files.exists(absent))
        }
        assertPassiveStatusReadsWithoutServiceMonitor(ownedService)
        WebJobService(JobStore(absent), JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor, Executor { error("Unexpected task") }).use { service ->
            service.initializeExistingStorage()
            assertPassiveStatusReadsWithoutServiceMonitor(service)
            assertIs<WebSchedulerSnapshot.Unavailable>(service.schedulerSnapshot())
            assertFalse(Files.exists(absent))
        }
    }

    @Test fun `retained report bytes deny upload before reading body and leave status readable`() = withStore { store, root ->
        val job = store.createFromUpload("quota.elf", elfFixture())
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports"))
        val retained = Files.createFile(reports.resolve("large-report"))
        java.nio.channels.FileChannel.open(retained, java.nio.file.StandardOpenOption.WRITE).use {
            it.position(WebUploadStorage.RESERVATION_BYTES)
            it.write(java.nio.ByteBuffer.wrap(byteArrayOf(0)))
        }
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor,
            maximumRetainedStorageBytes = WebUploadStorage.RESERVATION_BYTES).use { service ->
            service.initializeExistingStorage()
            val unread = object : java.io.InputStream() {
                override fun read(): Int = error("Quota refusal must precede request consumption")
            }
            assertEquals("UPLOAD_STORAGE", assertFailsWith<WebJobServiceException> {
                service.uploadMultipart(unread, "multipart/form-data; boundary=test")
            }.code)
            assertEquals(job.id, service.get(job.id).id)
            assertEquals(listOf(job.id), service.list().map { it.id })
            assertTrue(Files.exists(retained))
        }
    }

    @Test fun `stalled dashboard and API record reads leave unrelated status reads and uploads responsive`() = withStore { store, _ ->
        // Distinct attempt-store stripes: only the stalled record's own lock may be held.
        fun stripe(id: String) = (id.hashCode() and Int.MAX_VALUE) % 64
        val stalled = store.createFromUpload("stalled.elf", elfFixture())
        var other = store.createFromUpload("other.elf", elfFixture())
        while (stripe(other.id) == stripe(stalled.id)) other = store.createFromUpload("other.elf", elfFixture())
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            val listings = listOf<(WebJobService) -> List<String>>(
                { value -> value.dashboardRows().jobs.map { it.id } },
                { value -> value.collectionRecords().map { (it.getValue("jobId") as kotlinx.serialization.json.JsonPrimitive).content }.toList() },
            )
            // Count the stalled record's physical reads: workflow inspection, then legacy presentation.
            val recordReads = mutableListOf<String>()
            service.listingReadObserver = { relative -> if (relative.startsWith("${stalled.id}/")) recordReads += relative }
            service.dashboardRows()
            assertTrue(recordReads.size >= 2, "Expected separate workflow and presentation reads: $recordReads")
            val scenarios = listings.flatMap { listing -> listOf(1, recordReads.size).map { listing to it } }
            for ((listing, stalledRead) in scenarios) {
                val expected = store.jobIds().sorted()
                val entered = CountDownLatch(1)
                val release = CountDownLatch(1)
                val reads = AtomicInteger()
                service.listingReadObserver = { relative ->
                    if (relative.startsWith("${stalled.id}/") && reads.incrementAndGet() == stalledRead) {
                        entered.countDown()
                        check(release.await(20, TimeUnit.SECONDS))
                    }
                }
                val callers = Executors.newFixedThreadPool(2)
                try {
                    val pending = callers.submit<List<String>> { listing(service) }
                    assertTrue(entered.await(5, TimeUnit.SECONDS), "The listing did not reach its stalled record read")
                    // The listing is parked inside a physical record read; unrelated work must not wait for it.
                    val status = callers.submit<Pair<String, String>> {
                        service.get(other.id).id to (service.inspect(other.id) as WebJobInspection.Available).presentation.job.id
                    }.get(5, TimeUnit.SECONDS)
                    assertEquals(other.id to other.id, status)
                    callers.submit<WebSchedulerSnapshot> { service.schedulerSnapshot() }.get(5, TimeUnit.SECONDS)
                    val uploaded = callers.submit<String> { service.upload("concurrent.elf", elfFixture()).id }.get(5, TimeUnit.SECONDS)
                    assertEquals(uploaded, service.get(uploaded).id)
                    assertFalse(pending.isDone, "The stalled listing must still be in progress")
                    release.countDown()
                    // The listing enumerated its library before the upload; it neither fails nor invents rows.
                    assertEquals(expected, pending.get(5, TimeUnit.SECONDS).sorted())
                } finally {
                    release.countDown()
                    service.listingReadObserver = {}
                    callers.shutdownNow()
                    assertTrue(callers.awaitTermination(5, TimeUnit.SECONDS))
                }
            }
        }
    }

    @Test
    fun `startup reconciles orphan staging under ownership and releases lease when cleanup refuses storage`() = withStore { store, root ->
        val orphan = Files.createDirectory(root.resolve(".upload-stream-v1-123"), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        Files.writeString(orphan.resolve("input.elf"), "incomplete")
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            assertFalse(Files.exists(orphan))
            assertTrue(service.list().isEmpty())
            // Reads do not repeat maintenance after startup.
            Files.createDirectory(orphan, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            Files.writeString(orphan.resolve("unexpected.txt"), "preserve")
            assertTrue(service.list().isEmpty())
            assertTrue(Files.exists(orphan))
        }
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            val failure = assertFailsWith<decompengine.jobs.WorkflowStoreException> { service.initializeExistingStorage() }
            assertEquals("UPLOAD_STAGING_RECOVERY_REQUIRED", failure.code)
        }
        assertEquals("preserve", Files.readString(orphan.resolve("unexpected.txt")))
        decompengine.jobs.WorkflowAttemptStore.open(root).use { /* failed startup did not retain ownership */ }
    }

    @Test
    fun `upload and reads stay inert and explicit adapters share the same stored job`() = withStore { store, _ ->
        val operations = mutableListOf<String>()
        WebJobService(store, JobAnalyzer { job, _ -> operations += "explore:${job.id}" },
            JobReconstructor { job, _ -> operations += "reconstruct:${job.id}" }, Executor(Runnable::run)).use { service ->
            val job = service.upload("fixture.elf", elfFixture())
            assertEquals(job, service.get(job.id))
            assertEquals(listOf(job), service.list())
            assertTrue(operations.isEmpty())
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("complete", store.get(job.id).status)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.RECONSTRUCT))
            assertEquals(listOf("explore:${job.id}", "reconstruct:${job.id}"), operations)
        }
    }

    @Test
    fun `concurrent starts admit exactly one workflow for a job`() = withStore { store, _ ->
        val tasks = ConcurrentLinkedQueue<Runnable>()
        val executions = AtomicInteger()
        WebJobService(store, JobAnalyzer { _, _ -> executions.incrementAndGet() }, inertReconstructor,
            Executor { tasks.add(it) }).use { service ->
            val job = service.upload("concurrent.elf", elfFixture())
            val callers = Executors.newFixedThreadPool(8)
            try {
                val start = CountDownLatch(1)
                val results = (1..8).map {
                    callers.submit<WebWorkflowAdmission> {
                        check(start.await(5, TimeUnit.SECONDS))
                        service.start(job.id, WebWorkflow.EXPLORE)
                    }
                }
                start.countDown()
                val admissions = results.map { it.get(5, TimeUnit.SECONDS) }
                assertEquals(1, admissions.count { it is WebWorkflowAdmission.Started })
                assertEquals(7, admissions.count { it == WebWorkflowAdmission.AlreadyRunning })
                assertEquals(1, tasks.size)
                tasks.remove().run()
                assertEquals(1, executions.get())
                assertEquals("complete", service.get(job.id).status)
            } finally {
                callers.shutdownNow()
            }
        }
    }

    @Test
    fun `worker rejection releases admission and supports a deliberate later retry`() = withStore { store, _ ->
        val submissions = AtomicInteger()
        val executions = AtomicInteger()
        val executor = Executor { task ->
            if (submissions.getAndIncrement() == 0) throw RejectedExecutionException("private detail")
            task.run()
        }
        WebJobService(store, JobAnalyzer { _, _ -> executions.incrementAndGet() }, inertReconstructor, executor).use { service ->
            val job = service.upload("capacity.elf", elfFixture())
            assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("failed", service.get(job.id).status)
            assertEquals(0, executions.get())
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals(1, executions.get())
        }
    }

    @Test
    fun `unexpected submission failure preserves its cause and releases a retryable job`() = withStore { store, _ ->
        val submissions = AtomicInteger()
        val executor = Executor { task ->
            if (submissions.getAndIncrement() == 0) throw AssertionError("submission fixture")
            task.run()
        }
        WebJobService(store, JobAnalyzer { _, _ -> }, inertReconstructor, executor).use { service ->
            val job = service.upload("submission.elf", elfFixture())
            val failure = assertFailsWith<AssertionError> { service.start(job.id, WebWorkflow.EXPLORE) }
            assertEquals("submission fixture", failure.message)
            assertEquals("failed", service.get(job.id).status)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            assertEquals("complete", service.get(job.id).status)
        }
    }

    @Test
    fun `owned workers and waiting workflows are independently bounded`() = withStore { store, _ ->
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executed = AtomicInteger()
        WebJobService(store, JobAnalyzer { _, _ ->
            entered.countDown()
            check(release.await(5, TimeUnit.SECONDS))
            executed.incrementAndGet()
        }, inertReconstructor, workers = 1, queueCapacity = 1).use { service ->
            val jobs = (1..3).map { service.upload("bounded-$it.elf", elfFixture()) }
            try {
                assertIs<WebWorkflowAdmission.Started>(service.start(jobs[0].id, WebWorkflow.EXPLORE))
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                assertIs<WebWorkflowAdmission.Started>(service.start(jobs[1].id, WebWorkflow.EXPLORE))
                assertEquals(WebWorkflowAdmission.Unavailable, service.start(jobs[2].id, WebWorkflow.EXPLORE))
                assertEquals("queued", service.get(jobs[1].id).status)
                val sample = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
                assertEquals(1, sample.activeWorkers)
                assertEquals(1, sample.workerLimit)
                assertEquals(1, sample.queuedTasks)
                assertEquals(1, sample.queueCapacity)
                assertFalse(sample.stopping)
                release.countDown()
                await { jobs.take(2).all { service.get(it.id).status == "complete" } }
                assertEquals(2, executed.get())
            } finally {
                release.countDown()
            }
        }
    }

    @Test
    fun `close revokes borrowed pending tasks and late delivery is inert`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        var executions = 0
        val service = WebJobService(store, JobAnalyzer { _, _ -> executions++ }, inertReconstructor, Executor(tasks::add))
        val job = service.upload("pending.elf", elfFixture())
        assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
        service.close()
        val metadata = root.resolve(job.id).resolve("job.json")
        val before = Files.readString(metadata)
        assertEquals("failed", store.get(job.id).status)
        tasks.single().run()
        assertEquals(before, Files.readString(metadata))
        assertEquals(0, executions)
        assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.EXPLORE))
    }

    @Test
    fun `failed initial state transition cannot strand active job ownership`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        WebJobService(store, JobAnalyzer { _, _ -> }, inertReconstructor, Executor(tasks::add)).use { service ->
            val job = service.upload("damaged.elf", elfFixture())
            service.start(job.id, WebWorkflow.EXPLORE)
            val metadata = root.resolve(job.id).resolve("job.json")
            val before = Files.readString(metadata)
            Files.writeString(metadata, "{")
            assertFailsWith<Exception> { tasks.removeAt(0).run() }
            Files.writeString(metadata, before)
            assertIs<WebWorkflowAdmission.Started>(service.start(job.id, WebWorkflow.EXPLORE))
            tasks.removeAt(0).run()
            assertEquals("complete", service.get(job.id).status)
        }
    }

    @Test
    fun `shutdown continues revoking tasks after one damaged record`() = withStore { store, root ->
        val tasks = mutableListOf<Runnable>()
        var executions = 0
        val service = WebJobService(store, JobAnalyzer { _, _ -> executions++ }, inertReconstructor, Executor(tasks::add))
        val jobs = (1..2).map { service.upload("pending-$it.elf", elfFixture()) }
        jobs.forEach { service.start(it.id, WebWorkflow.EXPLORE) }
        Files.writeString(root.resolve(jobs[0].id).resolve("job.json"), "{")
        assertFailsWith<Exception> { service.close() }
        assertEquals("failed", store.get(jobs[1].id).status)
        tasks.forEach(Runnable::run)
        assertEquals(0, executions)
    }

    @Test
    fun `workflow failure stores a safe diagnostic without raw exception content`() = withStore { store, root ->
        WebJobService(store, JobAnalyzer { _, _ -> error("/private/operator SECRET_FIXTURE") }, inertReconstructor,
            Executor(Runnable::run)).use { service ->
            val job = service.upload("failed.elf", elfFixture())
            service.start(job.id, WebWorkflow.EXPLORE)
            assertEquals("failed", service.get(job.id).status)
            val persisted = Files.readString(root.resolve(job.id).resolve("job.json"))
            assertFalse(persisted.contains("SECRET_FIXTURE"))
            assertFalse(persisted.contains("/private/operator"))
        }
    }

    @Test
    fun `streamed upload confirms new store ancestors under ownership before publication`() = withStore { _, root ->
        val storage = root.resolve("new-store/nested/jobs")
        val confirmed = mutableListOf<Path>()
        val store = JobStore(storage, AtomicUploadPublisher, storeDirectories = JobStoreDirectories { selected ->
            decompengine.jobs.prepareJobStoreDirectories(selected) { directory ->
                if (confirmed.isEmpty()) {
                    assertEquals("OWNERSHIP_CONFLICT", assertFailsWith<WorkflowStoreException> {
                        WorkflowAttemptStore.open(selected)
                    }.code)
                    assertFalse(Files.newDirectoryStream(selected, ".upload-*").use { it.iterator().hasNext() })
                }
                forceJobStoreDirectory(directory)
                confirmed.add(directory)
            }
        })
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            service.initializeExistingStorage()
            assertFalse(Files.exists(storage))
            val boundary = "directory-confirmation"
            val binary = elfFixture()
            val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"confirmed.elf\"\r\n\r\n".toByteArray() +
                binary + "\r\n--$boundary--\r\n".toByteArray()
            val job = body.inputStream().use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
            val chain = generateSequence(storage.toRealPath()) { it.parent }.toList()
            assertEquals(chain, confirmed)
            kotlin.test.assertContentEquals(binary, Files.readAllBytes(job.binaryPath))
            assertEquals(listOf(job.id), service.list().map { it.id })
            assertEquals(chain, confirmed, "reads must not repeat initialization maintenance")
            println("job-store-directory-confirmation " + kotlinx.serialization.json.buildJsonObject {
                put("schemaVersion", kotlinx.serialization.json.JsonPrimitive(1))
                put("fixtureOnly", kotlinx.serialization.json.JsonPrimitive(true))
                put("ancestorCount", kotlinx.serialization.json.JsonPrimitive(chain.size))
                put("provider", kotlinx.serialization.json.JsonPrimitive(storage.fileSystem.provider().javaClass.name))
                put("filesystemTypes", kotlinx.serialization.json.JsonArray(chain.map { Files.getFileStore(it).type() }
                    .distinct().sorted().map { kotlinx.serialization.json.JsonPrimitive(it) }))
                for (name in listOf("java.runtime.version", "os.name", "os.arch")) {
                    put(name, kotlinx.serialization.json.JsonPrimitive(System.getProperty(name, "unavailable").take(128)))
                }
                put("underOwnership", kotlinx.serialization.json.JsonPrimitive(true))
                put("inputBytesPreserved", kotlinx.serialization.json.JsonPrimitive(true))
            })
        }
    }

    @Test
    fun `directory confirmation refusal preserves jobs releases ownership and retries before upload bytes`() = withStore { ordinary, root ->
        val prior = ordinary.createFromUpload("prior.elf", elfFixture())
        val metadata = root.resolve(prior.id).resolve("job.json")
        val before = Files.readAllBytes(metadata)
        val input = Files.readAllBytes(prior.binaryPath)
        val confirmed = mutableListOf<Path>()
        var refuse = true
        val store = JobStore(root, AtomicUploadPublisher, storeDirectories = JobStoreDirectories { selected ->
            prepareJobStoreDirectories(selected) { directory ->
                if (refuse && directory == root.toRealPath().parent) {
                    throw UnsupportedOperationException("PRIVATE-directory-provider-canary")
                }
                forceJobStoreDirectory(directory)
                confirmed.add(directory)
            }
        })
        WebJobService(store, JobAnalyzer { _, _ -> error("Unexpected execution") }, inertReconstructor).use { service ->
            val unread = object : java.io.InputStream() {
                override fun read(): Int = error("Directory refusal must precede request consumption")
            }
            val failure = assertFailsWith<WebJobServiceException> {
                service.uploadMultipart(unread, "multipart/form-data; boundary=unread")
            }
            assertEquals("STORE_DURABILITY_UNAVAILABLE", failure.code)
            assertEquals(failure.code, publicWebDiagnosticCode(failure.code))
            assertEquals(failure.message, publicWebDiagnosticMessage(failure.code))
            assertFalse(publicWebDiagnosticMessage(failure.code).contains("PRIVATE"))
            assertEquals(listOf(root.toRealPath()), confirmed)
            kotlin.test.assertContentEquals(before, Files.readAllBytes(metadata))
            kotlin.test.assertContentEquals(input, Files.readAllBytes(prior.binaryPath))
            assertFalse(Files.newDirectoryStream(root, ".upload-*").use { it.iterator().hasNext() })
            WorkflowAttemptStore.open(root).use { /* failed admission did not retain the root lease */ }
            refuse = false
            val boundary = "directory-retry"
            val body = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"retry.elf\"\r\n\r\n".toByteArray() +
                elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
            val uploaded = body.inputStream().use { service.uploadMultipart(it, "multipart/form-data; boundary=$boundary") }
            assertEquals(listOf(root.toRealPath()) + generateSequence(root.toRealPath()) { it.parent }.toList(), confirmed)
            assertEquals(setOf(prior.id, uploaded.id), service.list().map { it.id }.toSet())
            kotlin.test.assertContentEquals(before, Files.readAllBytes(metadata))
            kotlin.test.assertContentEquals(input, Files.readAllBytes(prior.binaryPath))
        }
    }

    /** Latches exercise only metadata reads on the existing fixture's service instance. */
    private fun assertPassiveStatusReadsWithoutServiceMonitor(service: WebJobService) {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val expected = java.util.concurrent.atomic.AtomicReference<Pair<Result<WebSchedulerSnapshot>, WebProgressRetentionStatus>>()
        val callers = java.util.concurrent.Executors.newFixedThreadPool(2)
        val holder = callers.submit {
            synchronized(service) {
                expected.set(runCatching { service.schedulerSnapshot() } to service.progressRetentionStatus())
                entered.countDown()
                check(release.await(20, TimeUnit.SECONDS))
            }
        }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val actual = callers.submit<Pair<Result<WebSchedulerSnapshot>, WebProgressRetentionStatus>> {
                runCatching { service.schedulerSnapshot() } to service.progressRetentionStatus()
            }.get(5, TimeUnit.SECONDS)
            val captured = expected.get()
            assertEquals(captured.second, actual.second)
            if (captured.first.isFailure) {
                assertEquals(assertIs<WebJobServiceException>(captured.first.exceptionOrNull()).code,
                    assertIs<WebJobServiceException>(actual.first.exceptionOrNull()).code)
            } else {
                val sample = actual.first.getOrThrow()
                when (val previous = captured.first.getOrThrow()) {
                    is WebSchedulerSnapshot.Available -> assertEquals(previous.copy(sampledAt = sample.sampledAt), sample)
                    is WebSchedulerSnapshot.Unavailable -> assertEquals(previous.copy(sampledAt = sample.sampledAt), sample)
                }
            }
        } finally {
            release.countDown()
            try { holder.get(5, TimeUnit.SECONDS) }
            finally {
                callers.shutdownNow()
                assertTrue(callers.awaitTermination(10, TimeUnit.SECONDS))
            }
        }
    }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!condition() && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(condition(), "Workflow did not reach its expected state within five seconds")
    }

    private fun withStore(block: (JobStore, Path) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build/test-tmp/web-job-service").toAbsolutePath())
        val root = createTempDirectory(temporaryRoot, "web-job-service-")
        try {
            block(JobStore(root), root)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private val inertReconstructor = JobReconstructor { _, _ -> }
}
