package decompengine.web

import decompengine.jobs.*
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.extension.ExtendWith
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.readBytes
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class DurableWebWorkflowStartTest {
    @Test
    fun `both durable start paths retain the trusted harness capability in execution and storage`() {
        for (capability in listOf(CAPABILITY, null)) withRoot { root ->
            val store = JobStore(root); val job = store.createFromUpload("capability.elf", elfFixture())
            val observed = mutableListOf<String?>()
            val registered = object : DurableWebWorkflowAdapter {
                override val workflow = WorkflowKind.RECONSTRUCT
                override val limits = LIMITS
                override val harnessCapabilityId = capability
                override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
                    observed.add(context.attempt.harnessCapabilityId)
                    return DurableWebWorkflowOutcome.Completed()
                }
            }
            service(store, listOf(registered)).use { service ->
                service.initializeExistingStorage()
                val legacy = assertIs<DurableWebWorkflowAdmission.Started>(service.startDurable(
                    job.id, version(service, job.id), DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT),
                ))
                val retained = service.getAttempt(job.id, legacy.runId)
                assertEquals(capability, retained.harnessCapabilityId)
                assertEquals(WorkflowRunState.COMPLETED, retained.state)
                val keyed = service.requestDurableStart(job.id, version(service, job.id),
                    REQUEST.copy(harnessCapabilityId = capability), KEY)
                assertEquals(capability, keyed.attempt.harnessCapabilityId)
                assertEquals(WorkflowRunState.COMPLETED, keyed.attempt.state)
                assertNotEquals(retained.runId, keyed.attempt.runId)
                assertEquals(listOf(capability, capability), observed)
            }
            WorkflowAttemptStore.open(root).use { owner ->
                val attempts = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot.attempts
                assertEquals(2, attempts.size)
                assertTrue(attempts.all { it.harnessCapabilityId == capability && it.state == WorkflowRunState.COMPLETED })
            }
        }
    }

    @Test
    fun `Git ownership refuses every workflow admission but not retained keyed replay`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("git-lease.elf", elfFixture())
        val queued = mutableListOf<Runnable>()
        service(store, executor = Executor(queued::add)).use { service ->
            service.initializeExistingStorage()
            val original = version(service, job.id)
            assertNotNull(service.gitWorkspaceLeases.tryGit(job.id)).use {
                assertEquals(WebWorkflowAdmission.Unavailable, service.start(job.id, WebWorkflow.RECONSTRUCT))
                assertEquals(DurableWebWorkflowAdmission.Unavailable("WORKTREE_BUSY"),
                    service.startDurable(job.id, original, DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
                assertCode("WORKTREE_BUSY") { service.requestDurableStart(job.id, original, REQUEST, KEY) }
                assertTrue(queued.isEmpty())
                assertTrue(service.gitRunActivity(job.id).values.none { it })
            }
            val started = service.requestDurableStart(job.id, original, REQUEST, KEY)
            assertEquals(1, queued.size)
            assertEquals(true, service.gitRunActivity(job.id)[started.attempt.runId])
            assertNotNull(service.gitWorkspaceLeases.tryGit(job.id)).use {
                assertTrue(service.requestDurableStart(job.id, original, REQUEST, KEY).replayed)
                assertCode("WORKTREE_BUSY") { service.requestDurableStart(job.id, version(service, job.id), REQUEST, OTHER_KEY) }
                assertEquals(1, queued.size)
            }
            queued.single().run()
            assertTrue(service.gitRunActivity(job.id).values.none { it })
            // Corrupt/unavailable workflow ownership must never be interpreted as an empty lease set.
            Files.writeString(state(root, job.id), "not a workflow record")
            assertEquals("WORKTREE_BUSY", assertFailsWith<decompengine.git.ManagedGitException> { service.gitRunActivity(job.id) }.code)
        }
    }

    @Test
    fun `public request version and storage CAS stay separate and old replay never dispatches later work`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("authored.elf", elfFixture())
        val calls = AtomicInteger()
        service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() })).use { service ->
            service.initializeExistingStorage()
            val originalVersion = version(service, job.id)
            val storageVersion = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.version
            assertNotEquals(storageVersion, originalVersion)
            val first = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY)
            assertFalse(first.replayed); assertEquals(WorkflowRunState.COMPLETED, first.attempt.state)
            assertEquals(originalVersion, first.attempt.startReceipt!!.expectedRequestVersion)
            assertNull(first.attempt.acceptedRevision)
            val later = service.requestDurableStart(job.id, version(service, job.id), REQUEST, OTHER_KEY)
            assertNotEquals(first.attempt.runId, later.attempt.runId)
            val before = state(root, job.id).readBytes()
            val replay = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY)
            assertTrue(replay.replayed); assertEquals(first.attempt, replay.attempt)
            assertEquals(later.attempt.runId, service.presentation(job.id).snapshot!!.latestRun!!.runId)
            assertEquals(2, calls.get()); assertContentEquals(before, state(root, job.id).readBytes())
            assertCode("VERSION_CONFLICT") { service.requestDurableStart(job.id, originalVersion, REQUEST, "new_stale_request_key") }
        }
    }

    @Test
    fun `queued replay after a pin change preserves the owned task version and dispatches once`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("queued.elf", elfFixture())
        val queued = mutableListOf<Runnable>(); val calls = AtomicInteger()
        service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor(queued::add)).use { service ->
            service.initializeExistingStorage(); val originalVersion = version(service, job.id)
            val first = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY)
            val pinned = service.setProgressRetentionPinned(job.id, first.attempt.runId, first.attempt.version, true)
            val before = state(root, job.id).readBytes()
            val replay = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY)
            assertTrue(replay.replayed); assertEquals(pinned.version, replay.attempt.version)
            assertTrue(replay.attempt.progressRetentionPinned)
            assertEquals(1, queued.size); assertContentEquals(before, state(root, job.id).readBytes())
            queued.single().run()
            assertEquals(1, calls.get())
            assertEquals(WorkflowRunState.COMPLETED, service.getAttempt(job.id, first.attempt.runId).state)
        }
    }

    @Test
    fun `key conflicts precede current registration validation and restart never requeues an interrupted run`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("reopen.elf", elfFixture())
        val queued = mutableListOf<Runnable>(); val calls = AtomicInteger()
        lateinit var originalVersion: String; lateinit var originalRun: String
        service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor(queued::add)).use { service ->
            service.initializeExistingStorage(); originalVersion = version(service, job.id)
            originalRun = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY).attempt.runId
            val variants = listOf(REQUEST.copy(workflow = WorkflowKind.REPAIR), REQUEST.copy(inputRevisionId = "revision_other"),
                REQUEST.copy(harnessCapabilityId = "harness_other"), REQUEST.copy(limits = LIMITS.copy(maxToolCalls = 17uL)))
            val before = state(root, job.id).readBytes()
            variants.forEach { changed -> assertCode("IDEMPOTENCY_CONFLICT") {
                service.requestDurableStart(job.id, originalVersion, changed, KEY)
            } }
            assertCode("IDEMPOTENCY_CONFLICT") { service.requestDurableStart(job.id, "version_different_intent", REQUEST, KEY) }
            assertContentEquals(before, state(root, job.id).readBytes()); assertEquals(1, queued.size)
        }
        service(store, emptyList(), Executor { error("restart must not enqueue work") }).use { service ->
            service.initializeExistingStorage(); val before = state(root, job.id).readBytes()
            val replay = service.requestDurableStart(job.id, originalVersion, REQUEST, KEY)
            assertTrue(replay.replayed); assertEquals(originalRun, replay.attempt.runId)
            assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
            assertContentEquals(before, state(root, job.id).readBytes())
        }
        queued.single().run(); assertEquals(0, calls.get())
    }

    @Test
    fun `owned worker and queue bounds reject new work without hiding an existing keyed run`() = withRoot { root ->
        val store = JobStore(root); val jobs = (1..3).map { store.createFromUpload("bounded-$it.elf", elfFixture()) }
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val calls = AtomicInteger()
        service(store, listOf(adapter {
            calls.incrementAndGet(); entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
            DurableWebWorkflowOutcome.Completed()
        }), executor = null, workers = 1, queueCapacity = 1).use { service ->
            service.initializeExistingStorage(); val firstVersion = version(service, jobs[0].id)
            try {
                val first = service.requestDurableStart(jobs[0].id, firstVersion, REQUEST, KEY)
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                val second = service.requestDurableStart(jobs[1].id, version(service, jobs[1].id), REQUEST, OTHER_KEY)
                assertEquals(WorkflowRunState.RUNNING, service.getAttempt(jobs[0].id, first.attempt.runId).state)
                assertEquals(WorkflowRunState.QUEUED, second.attempt.state)
                assertCode("ACTIVE_RUN") { service.requestDurableStart(jobs[0].id, version(service, jobs[0].id), REQUEST, OTHER_KEY) }
                assertCode("CAPACITY_UNAVAILABLE") { service.requestDurableStart(jobs[2].id, version(service, jobs[2].id), REQUEST, KEY) }
                assertTrue((service.inspectDurableJob(jobs[2].id) as WorkflowJobInspection.Available).snapshot.attempts.isEmpty())
                val replay = service.requestDurableStart(jobs[0].id, firstVersion, REQUEST, KEY)
                assertTrue(replay.replayed); assertEquals(first.attempt.runId, replay.attempt.runId)
                assertEquals(1, calls.get())
                val observed = assertIs<WebSchedulerSnapshot.Available>(service.schedulerSnapshot())
                assertEquals(1, observed.workerLimit); assertEquals(1, observed.queueCapacity)
                assertEquals(1, observed.activeWorkers); assertEquals(1, observed.queuedTasks)
            } finally { release.countDown() }
        }
    }

    @Test
    fun `invalid input capability limits version keys and recovery intent cannot admit or fall back`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("refusals.elf", elfFixture())
        val calls = AtomicInteger()
        service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() })).use { service ->
            service.initializeExistingStorage(); val current = version(service, job.id)
            assertCode("VERSION_CONFLICT") { service.requestDurableStart(job.id, "version_stale", REQUEST, KEY) }
            assertCode("WORKFLOW_UNAVAILABLE") { service.requestDurableStart(job.id, current, REQUEST.copy(workflow = WorkflowKind.REPAIR), KEY) }
            assertCode("HARNESS_UNAVAILABLE") { service.requestDurableStart(job.id, current, REQUEST.copy(harnessCapabilityId = "other_harness"), KEY) }
            assertCode("WORKFLOW_LIMITS_UNAVAILABLE") { service.requestDurableStart(job.id, current, REQUEST.copy(limits = LIMITS.copy(idleMs = 1uL)), KEY) }
            assertCode("INPUT_REVISION_UNAVAILABLE") { service.requestDurableStart(job.id, current, REQUEST.copy(inputRevisionId = "unaccepted_revision"), KEY) }
            assertCode("INVALID_WORKFLOW_REQUEST") { service.requestDurableStart(job.id, current, REQUEST.copy(previousRunId = "run_unknown"), KEY) }
            assertCode("INVALID_WORKFLOW_REQUEST") { service.requestDurableStart(job.id, "invalid version", REQUEST, KEY) }
            assertCode("INVALID_IDEMPOTENCY_KEY") { service.requestDurableStart(job.id, current, REQUEST, "bad/key") }
            assertCode("JOB_NOT_FOUND") { service.requestDurableStart("../outside", current, REQUEST, KEY) }
            assertTrue((service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.attempts.isEmpty())
            assertFalse(Files.exists(state(root, job.id))); assertEquals(0, calls.get())
        }
        val absent = root.resolve("absent")
        service(JobStore(absent), emptyList()).use { service ->
            service.initializeExistingStorage()
            assertCode("WORKFLOW_UNAVAILABLE") { service.requestDurableStart("f".repeat(32), "version_unused", REQUEST, KEY) }
            assertFalse(Files.exists(absent))
        }
    }

    @Test
    fun `concurrent identical starts dispatch once and conflicting valid workflows keep one winner`() {
        for (conflicting in listOf(false, true)) withRoot { root ->
            val store = JobStore(root); val job = store.createFromUpload("race.elf", elfFixture())
            val queued = mutableListOf<Runnable>(); val calls = AtomicInteger()
            val action: (DurableWebWorkflowContext) -> DurableWebWorkflowOutcome = { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }
            service(store, listOf(adapter(action = action), adapter(WorkflowKind.VALIDATE, action = action)), Executor(queued::add)).use { service ->
                service.initializeExistingStorage(); val current = version(service, job.id)
                val results = race { index -> service.requestDurableStart(job.id, current,
                    if (conflicting && index == 1) REQUEST.copy(workflow = WorkflowKind.VALIDATE) else REQUEST, KEY) }
                assertEquals(1, results.filterIsInstance<DurableWebWorkflowStartResult>().count { !it.replayed })
                if (conflicting) assertEquals(1, results.filterIsInstance<WebJobServiceException>().count { it.code == "IDEMPOTENCY_CONFLICT" })
                else {
                    assertEquals(1, results.filterIsInstance<DurableWebWorkflowStartResult>().count { it.replayed })
                    assertEquals(1, results.filterIsInstance<DurableWebWorkflowStartResult>().map { it.attempt.runId }.distinct().size)
                }
                assertEquals(1, queued.size); queued.single().run(); assertEquals(1, calls.get())
                assertEquals(1, (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.attempts.size)
            }
        }
    }

    @Test
    fun `executor submission failures retain a failed run and replay never retries scheduling`() {
        for (refused in listOf(true, false)) withRoot { root ->
            val store = JobStore(root); val job = store.createFromUpload("rejected.elf", elfFixture())
            val submissions = AtomicInteger(); val calls = AtomicInteger(); val late = mutableListOf<Runnable>()
            service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor {
                if (submissions.getAndIncrement() == 0) {
                    late += it // Failed submission does not prove that the executor discarded the task.
                    if (refused) throw RejectedExecutionException("authored refusal")
                    else throw IllegalStateException("PRIVATE scheduling diagnostic")
                }
                it.run()
            }).use { service ->
                service.initializeExistingStorage(); val current = version(service, job.id)
                val first = if (refused) service.requestDurableStart(job.id, current, REQUEST, KEY).attempt else {
                    assertCode("SCHEDULING_FAILED") { service.requestDurableStart(job.id, current, REQUEST, KEY) }
                    (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot.latestRun!!
                }
                assertEquals(WorkflowRunState.FAILED, first.state)
                assertEquals(if (refused) WorkflowTerminalReason.REFUSED else WorkflowTerminalReason.FAILED, first.terminalReason)
                assertNull(first.startedAt); assertNull(first.acceptedRevision)
                val before = state(root, job.id).readBytes()
                late.single().run()
                assertContentEquals(before, state(root, job.id).readBytes()); assertEquals(0, calls.get())
                val replay = service.requestDurableStart(job.id, current, REQUEST, KEY)
                assertTrue(replay.replayed); assertEquals(first, replay.attempt)
                assertEquals(1, submissions.get()); assertEquals(0, calls.get())
                val next = service.requestDurableStart(job.id, version(service, job.id), REQUEST, OTHER_KEY)
                assertNotEquals(first.runId, next.attempt.runId); assertEquals(WorkflowRunState.COMPLETED, next.attempt.state)
                assertEquals(2, submissions.get()); assertEquals(1, calls.get())
            }
        }
    }

    @Test
    fun `prepublication failure permits explicit retry but uncertain admission blocks all new work until recovery`() {
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_WRITE, WorkflowStoreFaultPoint.AFTER_RENAME)) withRoot { root ->
            val store = JobStore(root); val job = store.createFromUpload("fault.elf", elfFixture())
            val other = store.createFromUpload("other.elf", elfFixture())
            val armed = AtomicBoolean(); val queued = mutableListOf<Runnable>(); val calls = AtomicInteger()
            lateinit var current: String
            service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor(queued::add),
                fault = WorkflowStoreFaultInjector { if (it == point && armed.compareAndSet(true, false)) throw IOException("PRIVATE authored publication failure") }).use { service ->
                service.initializeExistingStorage(); current = version(service, job.id); armed.set(true)
                assertCode(if (point == WorkflowStoreFaultPoint.AFTER_RENAME) "RECOVERY_REQUIRED" else "PERSISTENCE_FAILED") {
                    service.requestDurableStart(job.id, current, REQUEST, KEY)
                }
                assertTrue(queued.isEmpty()); assertEquals(0, calls.get())
                if (point == WorkflowStoreFaultPoint.AFTER_RENAME) {
                    assertCode("RECOVERY_REQUIRED") { service.requestDurableStart(job.id, current, REQUEST, KEY) }
                    assertCode("RECOVERY_REQUIRED") { service.requestDurableStart(other.id, "version_unused", REQUEST, OTHER_KEY) }
                    assertEquals(WebWorkflowAdmission.Unavailable, service.start(other.id, WebWorkflow.EXPLORE))
                    assertCode("RECOVERY_REQUIRED") { service.upload("blocked.elf", elfFixture()) }
                } else {
                    val retry = service.requestDurableStart(job.id, current, REQUEST, KEY)
                    assertFalse(retry.replayed); assertEquals(1, queued.size)
                    queued.single().run(); assertEquals(1, calls.get())
                }
            }
            if (point == WorkflowStoreFaultPoint.AFTER_RENAME) service(store, emptyList(), Executor { error("recovery must not dispatch") }).use { service ->
                service.initializeExistingStorage()
                val replay = service.requestDurableStart(job.id, current, REQUEST, KEY)
                assertTrue(replay.replayed); assertEquals(WorkflowRunState.INTERRUPTED, replay.attempt.state)
                assertNull(replay.attempt.acceptedRevision); assertEquals(0, calls.get())
            }
        }
    }

    @Test
    fun `uncertain terminal publication preserves the original candidate without accepting or executing it again`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("terminal.elf", elfFixture())
        val armed = AtomicBoolean(); val calls = AtomicInteger(); lateinit var current: String
        val candidate = WorkflowCandidate("candidate_observed", "a".repeat(64))
        service(store, listOf(adapter {
            calls.incrementAndGet(); armed.set(true); DurableWebWorkflowOutcome.Completed(candidate)
        }), fault = WorkflowStoreFaultInjector {
            if (it == WorkflowStoreFaultPoint.AFTER_RENAME && armed.compareAndSet(true, false)) throw IOException("authored terminal publication failure")
        }).use { service ->
            service.initializeExistingStorage(); current = version(service, job.id)
            assertCode("RECOVERY_REQUIRED") { service.requestDurableStart(job.id, current, REQUEST, KEY) }
            assertCode("RECOVERY_REQUIRED") { service.requestDurableStart(job.id, current, REQUEST, KEY) }
            assertEquals(1, calls.get())
        }
        service(store, emptyList(), Executor { error("terminal replay must not dispatch") }).use { service ->
            service.initializeExistingStorage()
            val replay = service.requestDurableStart(job.id, current, REQUEST, KEY)
            assertTrue(replay.replayed); assertEquals(WorkflowRunState.COMPLETED, replay.attempt.state)
            assertEquals(candidate, replay.attempt.candidate); assertNull(replay.attempt.acceptedRevision)
            assertTrue(replay.attempt.publicationPending); assertEquals(1, calls.get())
        }
    }

    @Test
    fun `stopping service allows only retained replay and a stopped service never reacquires storage`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("stopping.elf", elfFixture())
        val queued = mutableListOf<Runnable>(); val calls = AtomicInteger()
        val service = service(store, listOf(adapter { calls.incrementAndGet(); DurableWebWorkflowOutcome.Completed() }), Executor(queued::add))
        lateinit var current: String
        service.use {
            service.initializeExistingStorage(); current = version(service, job.id)
            val first = service.requestDurableStart(job.id, current, REQUEST, KEY)
            service.beginShutdown()
            assertTrue(service.requestDurableStart(job.id, current, REQUEST, KEY).replayed)
            assertCode("SERVICE_STOPPED") { service.requestDurableStart(job.id, version(service, job.id), REQUEST, OTHER_KEY) }
            assertEquals(WorkflowRunState.QUEUED, first.attempt.state); assertEquals(1, queued.size)
        }
        val before = state(root, job.id).readBytes()
        assertCode("SERVICE_STOPPED") { service.requestDurableStart(job.id, current, REQUEST, KEY) }
        queued.single().run(); assertEquals(0, calls.get()); assertContentEquals(before, state(root, job.id).readBytes())
        WorkflowAttemptStore.open(root).use { owner -> assertTrue((owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot.latestRun!!.state.terminal) }
    }

    @Test
    fun `accepted input is bound to its job and never promotes the new attempt to acceptance`() = withRoot { root ->
        val store = JobStore(root); val job = store.createFromUpload("accepted.elf", elfFixture())
        val other = store.createFromUpload("foreign.elf", elfFixture()); lateinit var reference: WorkflowAcceptanceReference
        WorkflowAttemptStore.open(root).use { owner ->
            val initial = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            val queued = owner.create(job.id, initial.version, REQUEST)
            val running = owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val done = owner.transition(job.id, running.attempt.runId, running.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate("accepted_one", "a".repeat(64))))
            reference = WorkflowAcceptanceReference(job.id, done.attempt.runId, "accepted_one", "a".repeat(64), "graph_one", "artifact_one", "b".repeat(64))
            owner.recordAcceptedRevision(job.id, done.attempt.runId, done.snapshot.version, done.attempt.version, reference)
        }
        service(store).use { service ->
            service.initializeExistingStorage(); val request = REQUEST.copy(inputRevisionId = "accepted_one")
            assertCode("INPUT_REVISION_UNAVAILABLE") { service.requestDurableStart(other.id, version(service, other.id), request, KEY) }
            val started = service.requestDurableStart(job.id, version(service, job.id), request, KEY)
            assertEquals("accepted_one", started.attempt.inputRevisionId); assertNull(started.attempt.acceptedRevision)
            assertEquals(reference, service.presentation(job.id).snapshot!!.acceptedRevision)
        }
    }

    private fun adapter(kind: WorkflowKind = WorkflowKind.RECONSTRUCT,
        action: (DurableWebWorkflowContext) -> DurableWebWorkflowOutcome = { DurableWebWorkflowOutcome.Completed() }) = object : DurableWebWorkflowAdapter {
        override val workflow = kind
        override val limits = LIMITS
        override val harnessCapabilityId = CAPABILITY
        override fun execute(context: DurableWebWorkflowContext) = action(context)
    }
    private fun service(store: JobStore, adapters: List<DurableWebWorkflowAdapter> = listOf(adapter()),
        executor: Executor? = Executor(Runnable::run), workers: Int = 2, queueCapacity: Int = 32,
        fault: WorkflowStoreFaultInjector = WorkflowStoreFaultInjector {}) = WebJobService(store,
        JobAnalyzer { _, _ -> throw AssertionError("legacy analyzer fallback") },
        JobReconstructor { _, _ -> throw AssertionError("legacy reconstructor fallback") }, executor,
        workers = workers, queueCapacity = queueCapacity, durableAdapters = adapters,
        attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC(), fault) })
    private fun version(service: WebJobService, jobId: String) = webJob(service.presentation(jobId)).getValue("version").jsonPrimitive.content
    private fun state(root: Path, jobId: String) = root.resolve(jobId).resolve("workflow-state.json")
    private fun assertCode(code: String, operation: () -> Unit) = assertEquals(code, assertFailsWith<WebJobServiceException> { operation() }.code)
    private fun withRoot(operation: (Path) -> Unit) {
        val root = createTempDirectory("durable-keyed-start-")
        try { operation(root) } finally { root.toFile().deleteRecursively() }
    }
    private fun race(operation: (Int) -> Any): List<Any> {
        val ready = CountDownLatch(2); val release = CountDownLatch(1); val pool = Executors.newFixedThreadPool(2)
        try {
            val futures = (0..1).map { index -> pool.submit<Any> {
                ready.countDown(); check(release.await(5, TimeUnit.SECONDS))
                try { operation(index) } catch (failure: Exception) { failure }
            } }
            check(ready.await(5, TimeUnit.SECONDS)); release.countDown()
            return futures.map { it.get(10, TimeUnit.SECONDS) }
        } finally { release.countDown(); pool.shutdownNow() }
    }
    private companion object {
        const val CAPABILITY = "authored_harness"
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)
        val REQUEST = NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, harnessCapabilityId = CAPABILITY)
        const val KEY = "operator_start_request_123456"
        const val OTHER_KEY = "operator_start_request_second"
    }
}
