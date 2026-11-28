package decompengine.web

import com.sun.net.httpserver.*
import decompengine.jobs.*
import decompengine.testing.RecoveryMatrixEvidence
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import kotlinx.serialization.json.*
import org.junit.jupiter.api.extension.ExtendWith
import java.io.*
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.*
import java.nio.file.Files
import java.nio.file.Path
import java.time.Clock
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.readBytes
import kotlin.test.*

/** Inert deterministic adapters qualify the recovery transport/storage contract, not production runtime readiness. */
@ExtendWith(RecoveryMatrixEvidence::class)
class WebRecoveryControllerTest {
    private class Fixture(
        val root: Path = createTempDirectory("web-recovery-http-"),
        reuseJob: String? = null,
        registered: Boolean = true,
        @Volatile var deferred: Boolean = false,
        val checkpoints: DurableWebWorkflowCheckpointPolicy? = null,
        val captureBytes: (DurableWebWorkflowCheckpointRequest) -> ByteArray = { CONTINUATION_BYTES },
        val afterCapture: (DurableWebWorkflowCheckpointRequest) -> Unit = {},
        val beforeLaunch: () -> Unit = {},
        val duringLaunch: () -> Unit = {},
        seed: ((WorkflowAttemptStore, String) -> Unit)? = null,
        private val deleteRoot: Boolean = true,
    ) : AutoCloseable {
        val store = JobStore(root)
        val job = reuseJob?.let(store::get) ?: store.createFromUpload("authored.elf", elfFixture())
        val contexts = CopyOnWriteArrayList<DurableWebWorkflowContext>()
        val restored = CopyOnWriteArrayList<ByteArray>()
        val outcomes = ConcurrentLinkedQueue<DurableWebWorkflowOutcome>()
        val pending = ConcurrentLinkedQueue<Runnable>()
        @Volatile var fault: WorkflowStoreFaultPoint? = null
        val service: WebJobService
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val workers = Executors.newFixedThreadPool(2)
        val client: HttpClient = HttpClient.newHttpClient()
        val api: WebApiController
        val runs = "/workbench/api/v1/jobs/${job.id}/runs"
        val cookie: String
        val csrf: String
        init {
            seed?.let { operation -> WorkflowAttemptStore.open(root).use { operation(it, job.id) } }
            val policy = checkpoints
            service = WebJobService(store,
                JobAnalyzer { _, _ -> error("PRIVATE_RECOVERY_ANALYZER_FALLBACK") },
                JobReconstructor { _, _ -> error("PRIVATE_RECOVERY_RECONSTRUCTOR_FALLBACK") },
                Executor { task -> if (deferred) pending.add(task) else task.run() }, workers = 1, queueCapacity = 1,
                durableAdapters = if (!registered) emptyList() else listOf(object : DurableWebWorkflowAdapter {
                    override val workflow = WorkflowKind.RECONSTRUCT
                    override val limits = LIMITS
                    override val harnessCapabilityId = CAPABILITY
                    override val checkpoints = policy
                    override val continuation = if (policy == null) null else object : DurableWebWorkflowContinuation {
                        override fun capture(request: DurableWebWorkflowCheckpointRequest): VerifiedWebCheckpoint {
                            val captured = VerifiedWebCheckpoint(captureBytes(request), WorkflowResumeRestoration.PROJECT_EVIDENCE)
                            afterCapture(request)
                            return captured
                        }
                        override fun continueFrom(context: DurableWebWorkflowContext, checkpoint: VerifiedWebCheckpoint,
                            fence: DurableWebWorkflowContinuationFence): DurableWebWorkflowOutcome {
                            beforeLaunch()
                            fence.launch({ checkpoint.bytes() }) { bytes ->
                                contexts += context
                                restored += bytes
                                duringLaunch()
                            }
                            return outcomes.poll() ?: DurableWebWorkflowOutcome.Failed()
                        }
                    }
                    override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
                        contexts += context
                        return outcomes.poll() ?: DurableWebWorkflowOutcome.Failed()
                    }
                }), attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC(), WorkflowStoreFaultInjector { point ->
                    if (point == fault) throw IOException("PRIVATE_RECOVERY_PERSISTENCE_CANARY")
                }) })
            api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/workbench/"), service,
                WebJobMutationBoundary(access, service), resources)
            service.initializeExistingStorage()
            server.executor = workers; server.createContext("/") { check(api.route(it)) }; server.start()
            val session = send("POST", "{\"token\":\"${access.issueBootstrap().token}\"}",
                mapOf("Origin" to origin, "Content-Type" to "application/json"), "/workbench/api/v1/session")
            check(session.statusCode() == 200)
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }
        fun jobVersion() = webJob(service.presentation(job.id)).getValue("version").jsonPrimitive.content
        fun mutation(version: String, key: String) = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun start(key: String = "http_recovery_start_key_1"): String {
            val body = "{\"workflow\":\"reconstruct\",\"inputRevisionId\":null,\"harnessCapabilityId\":\"$CAPABILITY\"," +
                "\"limits\":{\"wallClockMs\":\"60000\",\"idleMs\":\"15000\",\"maxOutputBytes\":\"1048576\",\"maxToolCalls\":\"16\"}}"
            val response = send(body = body, headers = mutation(jobVersion(), key), target = runs)
            check(response.statusCode() == 202) { response.body() }
            return Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("runId").jsonPrimitive.content
        }
        fun attempt(runId: String) = service.getAttempt(job.id, runId)
        fun recover(runId: String, mode: String = "retry", key: String = KEY, version: String = attempt(runId).version,
            input: String? = null, body: String = recoverBody(mode, input), headers: Map<String, String> = mutation(version, key)) =
            send(body = body, headers = headers, target = "$runs/$runId/recover")
        fun controls(runId: String): Pair<HttpResponse<String>, JsonObject> {
            val response = send("GET", null, mapOf("Cookie" to cookie), "$runs/$runId/controls")
            assertEquals(200, response.statusCode(), response.body())
            val document = Json.parseToJsonElement(response.body()).jsonObject
            assertEquals("attemptControls", document.getValue("kind").jsonPrimitive.content)
            return response to document.getValue("data").jsonObject
        }
        fun send(method: String = "POST", body: String? = null, headers: Map<String, String> = emptyMap(), target: String): HttpResponse<String> {
            val b = HttpRequest.newBuilder(URI(origin + target)).timeout(Duration.ofSeconds(5)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofString(it) } ?: HttpRequest.BodyPublishers.noBody())
            b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun memory(runId: String, body: ByteArray, headers: Map<String, String>): MemoryExchange =
            MemoryExchange("POST", "$runs/$runId/recover", ObservedInput(body), server.address.port).apply {
                requestHeaders.set("Host", URI(origin).rawAuthority); requestHeaders.set("Accept", "application/json")
                headers.forEach { (k, v) -> requestHeaders.set(k, v) }
            }
        fun snapshot() = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot
        fun state() = root.resolve(job.id).resolve("workflow-state.json")
        override fun close() {
            fault = null; server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS)); client.close(); access.close(); service.close()
            if (deleteRoot) root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `retry publishes one new linked attempt and keyed replay returns it without rescheduling`() = Fixture().use { f ->
        val failed = f.start()
        assertEquals(WorkflowRunState.FAILED, f.attempt(failed).state)
        val (read, before) = f.controls(failed)
        assertEquals("\"${f.attempt(failed).version}\"", read.headers().firstValue("ETag").orElseThrow())
        assertEquals(control(true, null), before.getValue("retry"))
        assertEquals(control(false, "ATTEMPT_TERMINAL"), before.getValue("cancel"))
        assertEquals(control(false, "RESUME_UNSUPPORTED"), before.getValue("resume")); assertEquals(JsonNull, before["resumeRestores"])
        assertEquals(JsonNull, before["successorRunId"])
        val predecessorBytes = Json.parseToJsonElement(webRun(f.attempt(failed)).toString())
        f.outcomes += DurableWebWorkflowOutcome.Completed()
        val response = f.recover(failed); val retried = run(response)
        val id = retried.getValue("runId").jsonPrimitive.content
        assertNotEquals(failed, id)
        assertEquals(failed, retried.getValue("previousRunId").jsonPrimitive.content)
        assertEquals(buildJsonObject { put("mode", "retry"); put("restores", JsonNull); put("checkpointSha256", JsonNull) }, retried["recovery"])
        assertEquals("completed", retried.getValue("state").jsonPrimitive.content)
        assertEquals("${f.runs}/$id", response.headers().firstValue("Location").orElseThrow())
        assertEquals(2, f.contexts.size); assertNull(f.contexts.last().predecessorReportsDirectory)
        assertTrue(f.restored.isEmpty())
        // The predecessor is unchanged; retry restores nothing from it.
        assertEquals(predecessorBytes, Json.parseToJsonElement(webRun(f.attempt(failed)).toString()))
        val stored = f.state().readBytes()
        val replay = f.recover(failed, version = f.attempt(failed).version)
        assertEquals(id, run(replay).getValue("runId").jsonPrimitive.content)
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertContentEquals(stored, f.state().readBytes()); assertEquals(2, f.contexts.size)
        error(f.recover(failed, mode = "resume"), 409, "IDEMPOTENCY_CONFLICT")
        val after = f.controls(failed).second
        assertEquals(id, after.getValue("successorRunId").jsonPrimitive.content)
        assertEquals(control(false, "ATTEMPT_SUPERSEDED"), after.getValue("retry"))
        error(f.recover(failed, key = "http_recovery_fresh_key_2"), 409, "ATTEMPT_SUPERSEDED")
        assertEquals(control(false, "ATTEMPT_COMPLETED"), f.controls(id).second.getValue("retry"))
        error(f.recover(id, key = "http_recovery_fresh_key_3"), 409, "ATTEMPT_COMPLETED")
        error(f.recover(id, key = "http_recovery_fresh_key_4", version = "stale_run_version"), 412, "VERSION_CONFLICT")
        assertEquals(2, f.snapshot().attempts.size); assertNull(f.snapshot().acceptedRevision)
    }

    @Test
    fun `resume requires a verified checkpoint and exact harness and records what it restores`() {
        var decision: () -> DurableWebWorkflowCheckpoint = {
            DurableWebWorkflowCheckpoint.Refused(DurableWebWorkflowCheckpointRefusal.WORKSPACE_UNVERIFIED)
        }
        val inspected = CopyOnWriteArrayList<DurableWebWorkflowCheckpointRequest>()
        Fixture(checkpoints = { request -> inspected += request; decision() }).use { f ->
            val failed = f.start()
            assertEquals(control(false, "WORKSPACE_UNVERIFIED"), f.controls(failed).second.getValue("resume"))
            assertEquals(control(true, null), f.controls(failed).second.getValue("retry"))
            error(f.recover(failed, mode = "resume"), 409, "WORKSPACE_UNVERIFIED")
            decision = { error("PRIVATE_RECOVERY_CHECKPOINT_CANARY") }
            error(f.recover(failed, mode = "resume", key = "http_recovery_resume_key_2"), 409, "CHECKPOINT_UNVERIFIED")
            assertEquals(1, f.snapshot().attempts.size); assertEquals(1, f.contexts.size)
            decision = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) }
            val available = f.controls(failed).second
            assertEquals(control(true, null), available.getValue("resume"))
            assertEquals("project-evidence", available.getValue("resumeRestores").jsonPrimitive.content)
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            val resumed = run(f.recover(failed, mode = "resume", key = "http_recovery_resume_key_3"))
            assertEquals(buildJsonObject { put("mode", "resume"); put("restores", "project-evidence"); put("checkpointSha256", SHA) }, resumed["recovery"])
            val context = f.contexts.last()
            assertEquals(WorkflowRecoveryMode.RESUME, context.attempt.recovery!!.mode)
            assertNull(context.predecessorReportsDirectory)
            assertContentEquals(CONTINUATION_BYTES, f.restored.single())
            assertTrue(inspected.all { it.predecessor.runId == failed && it.job.id == f.job.id })
            assertEquals(CAPABILITY, resumed.getValue("harnessCapabilityId").jsonPrimitive.content)
        }
    }

    @Test
    fun `a duplicate published during inspection is replayed before predecessor checks`() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val inspections = java.util.concurrent.atomic.AtomicInteger()
        Fixture(checkpoints = {
            if (inspections.getAndIncrement() == 0) {
                entered.countDown()
                check(release.await(10, TimeUnit.SECONDS))
            }
            DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE)
        }).use { f ->
            val failed = f.attempt(f.start())
            f.deferred = true
            val executor = Executors.newSingleThreadExecutor()
            fun request() = f.service.requestDurableRecovery(f.job.id, failed.runId, failed.version, WorkflowRecoveryMode.RESUME, null, KEY)
            try {
                val first = executor.submit<DurableWebWorkflowStartResult> { request() }
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                val published = request()
                assertFalse(published.replayed)
                release.countDown()
                val replay = first.get(3, TimeUnit.SECONDS)
                assertTrue(replay.replayed)
                assertEquals(published.attempt, replay.attempt)
                assertEquals(1, f.pending.size)
                assertEquals(2, inspections.get())
            } finally {
                release.countDown()
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun `controls expose a closed refusal when the inspected version changes`() {
        lateinit var fixture: Fixture
        Fixture(checkpoints = { request ->
            fixture.service.setProgressRetentionPinned(request.job.id, request.predecessor.runId, request.predecessor.version, true)
            DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE)
        }).use { f ->
            fixture = f
            val id = f.start()
            val data = f.controls(id).second
            assertEquals(control(false, "CHECKPOINT_UNVERIFIED"), data.getValue("resume"))
            assertEquals(f.attempt(id).version, data.getValue("runVersion").jsonPrimitive.content)
            assertNull(data["resumeRestores"]?.takeUnless { it == JsonNull })
        }
    }

    @Test
    fun `blocked eligibility and admission inspections permit unrelated status and recheck a racing retry`() {
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        Fixture(checkpoints = {
            entered.countDown()
            check(release.await(10, TimeUnit.SECONDS))
            DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE)
        }).use { f ->
            val failed = f.attempt(f.start())
            val other = f.store.createFromUpload("other.elf", elfFixture())
            val workers = Executors.newFixedThreadPool(3)
            try {
                val controls = workers.submit<WebAttemptControls> { f.service.attemptControls(f.job.id, failed.runId) }
                val resume = workers.submit<String> {
                    assertFailsWith<WebJobServiceException> {
                        f.service.requestDurableRecovery(f.job.id, failed.runId, failed.version,
                            WorkflowRecoveryMode.RESUME, null, "blocked_resume_key")
                    }.code
                }
                assertTrue(entered.await(3, TimeUnit.SECONDS))
                val retry = workers.submit<WorkflowAttempt> {
                    assertEquals("CAPACITY_UNAVAILABLE", f.service.attemptControls(f.job.id, failed.runId).resumeReason)
                    assertEquals(other.id, f.service.presentation(other.id).job.id)
                    f.service.requestDurableRecovery(f.job.id, failed.runId, failed.version,
                        WorkflowRecoveryMode.RETRY, null, "racing_retry_key_01").attempt
                }.get(3, TimeUnit.SECONDS)
                release.countDown()
                assertEquals("ATTEMPT_SUPERSEDED", controls.get(3, TimeUnit.SECONDS).resumeReason)
                assertEquals("ATTEMPT_SUPERSEDED", resume.get(3, TimeUnit.SECONDS))
                assertEquals(retry.runId, f.snapshot().latestRun?.runId)
                assertEquals(2, f.snapshot().attempts.size)
                assertTrue(f.restored.isEmpty())
            } finally {
                release.countDown()
                workers.shutdownNow()
                assertTrue(workers.awaitTermination(3, TimeUnit.SECONDS))
            }
        }
    }

    @Test
    fun `checkpoint substitution in the queue refuses before execution and replays the same successor`() {
        val policy = DurableWebWorkflowCheckpointPolicy { request ->
            val bytes = request.predecessorReportsDirectory.resolve("checkpoint").readBytes()
            DurableWebWorkflowCheckpoint.Verified(decompengine.project.sha256(bytes), WorkflowResumeRestoration.PROJECT_EVIDENCE)
        }
        Fixture(checkpoints = policy, captureBytes = { it.predecessorReportsDirectory.resolve("checkpoint").readBytes() }).use { f ->
            val predecessor = f.start()
            val reports = f.contexts.single().reportsDirectory
            val file = Files.write(reports.resolve("checkpoint"), CONTINUATION_BYTES)
            val version = f.attempt(predecessor).version
            val before = f.state().readBytes()
            fun inventory() = Files.walk(f.root).use { entries -> entries.map(f.root::relativize).sorted().toList() }
            val beforeFiles = inventory()

            repeat(2) { assertEquals(control(true, null), f.controls(predecessor).second.getValue("resume")) }
            assertContentEquals(before, f.state().readBytes())
            assertContentEquals(CONTINUATION_BYTES, file.readBytes())
            assertEquals(beforeFiles, inventory())

            f.deferred = true
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            assertEquals(WorkflowRunState.QUEUED, f.attempt(successor).state)
            Files.writeString(file, "changed while queued")
            f.pending.remove().run()
            assertEquals(WorkflowRunState.FAILED, f.attempt(successor).state)
            assertEquals(WorkflowTerminalReason.REFUSED, f.attempt(successor).terminalReason)
            assertNull(f.snapshot().acceptedRevision)
            assertNull(f.attempt(successor).candidate)
            assertEquals(1, f.contexts.size)
            assertTrue(f.restored.isEmpty())
            val after = f.state().readBytes()
            val replay = f.recover(predecessor, mode = "resume", version = version)
            assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
            assertEquals(successor, run(replay).getValue("runId").jsonPrimitive.content)
            assertContentEquals(after, f.state().readBytes())
            assertTrue(f.pending.isEmpty())
        }
    }

    @Test
    fun `a queued successor cannot replace its admitted recovery and checkpoint together`() {
        val replacement = "replacement".toByteArray()
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            captureBytes = { replacement }).use { f ->
            val predecessor = f.start()
            f.deferred = true
            val id = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            val record = Files.readString(f.state())
            assertEquals(1, Regex(SHA).findAll(record).count())
            Files.writeString(f.state(), record.replace(SHA, decompengine.project.sha256(replacement)))
            f.pending.remove().run()
            assertEquals(WorkflowTerminalReason.REFUSED, f.attempt(id).terminalReason)
            assertEquals(1, f.contexts.size)
            assertTrue(f.restored.isEmpty())
        }
    }

    @Test
    fun `pinning both the successor and predecessor during capture preserves the admitted continuation`() {
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            afterCapture = { request ->
                val running = fixture.snapshot().latestRun!!
                fixture.service.setProgressRetentionPinned(fixture.job.id, running.runId, running.version, true)
                val previous = request.predecessor
                fixture.service.setProgressRetentionPinned(fixture.job.id, previous.runId, previous.version, true)
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            val id = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            assertEquals(WorkflowRunState.COMPLETED, f.attempt(id).state)
            assertTrue(f.attempt(id).progressRetentionPinned)
            assertTrue(f.attempt(predecessor).progressRetentionPinned)
            assertContentEquals(CONTINUATION_BYTES, f.restored.single())
        }
    }

    @Test
    fun `uncertain cancellation publication during capture prevents continuation`() {
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            afterCapture = {
                val running = fixture.snapshot().latestRun!!
                fixture.fault = WorkflowStoreFaultPoint.AFTER_RENAME
                val failure = assertFailsWith<WebJobServiceException> {
                    fixture.service.cancelDurable(fixture.job.id, running.runId, running.version)
                }
                assertEquals("RECOVERY_REQUIRED", failure.code)
                fixture.fault = null
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.deferred = true
            run(f.recover(predecessor, mode = "resume"))
            val failure = assertFailsWith<WebJobServiceException> { f.pending.remove().run() }
            assertEquals("RECOVERY_REQUIRED", failure.code)
            assertTrue(f.restored.isEmpty())
            assertEquals(1, f.contexts.size)
        }
    }

    @Test
    fun `cancellation after the last ownership check refuses the continuation launch`() {
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            beforeLaunch = {
                val running = fixture.snapshot().latestRun!!
                fixture.service.cancelDurable(fixture.job.id, running.runId, running.version)
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.deferred = true
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            try { f.pending.remove().run() } finally { Thread.interrupted() }
            assertEquals(WorkflowRunState.CANCELLED, f.attempt(successor).state)
            assertEquals(WorkflowTerminalReason.CANCELLED, f.attempt(successor).terminalReason)
            assertNull(f.attempt(successor).candidate)
            assertTrue(f.restored.isEmpty())
            assertEquals(1, f.contexts.size)
        }
    }

    @Test
    fun `uncertain cancellation publication after the last ownership check refuses the continuation launch`() {
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            beforeLaunch = {
                val running = fixture.snapshot().latestRun!!
                fixture.fault = WorkflowStoreFaultPoint.AFTER_RENAME
                val failure = assertFailsWith<WebJobServiceException> {
                    fixture.service.cancelDurable(fixture.job.id, running.runId, running.version)
                }
                assertEquals("RECOVERY_REQUIRED", failure.code)
                fixture.fault = null
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.deferred = true
            run(f.recover(predecessor, mode = "resume"))
            val failure = assertFailsWith<WebJobServiceException> { f.pending.remove().run() }
            assertEquals("RECOVERY_REQUIRED", failure.code)
            assertTrue(f.restored.isEmpty())
            assertEquals(1, f.contexts.size)
        }
    }

    @Test
    fun `an independent shutdown signal between the fence check and launch refuses the start`() {
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) }).use { f ->
            val predecessor = f.start()
            f.deferred = true
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            val signalled = java.util.concurrent.atomic.AtomicBoolean()
            f.service.continuationLaunchObserver = {
                // The shutdown path never takes the service monitor this check holds, so the signal completes here.
                val signaller = Thread({ f.service.signalShutdown(); signalled.set(true) }, "independent-shutdown-signal")
                signaller.start()
                signaller.join(TimeUnit.SECONDS.toMillis(5))
                check(signalled.get()) { "the shutdown signal did not complete" }
            }
            try { f.pending.remove().run() } finally { Thread.interrupted() }
            assertTrue(signalled.get())
            assertTrue(f.restored.isEmpty(), "no continuation may start after the shutdown signal")
            assertEquals(1, f.contexts.size)
            assertEquals(WorkflowRunState.INTERRUPTED, f.attempt(successor).state)
            assertEquals(WorkflowTerminalReason.PROCESS_INTERRUPTED, f.attempt(successor).terminalReason)
            assertNull(f.attempt(successor).candidate)
        }
    }

    @Test
    fun `a shutdown signal after the launch permit interrupts the started continuation`() {
        val interrupted = java.util.concurrent.atomic.AtomicBoolean()
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            duringLaunch = {
                val signaller = Thread({ fixture.service.signalShutdown() }, "post-launch-shutdown-signal")
                signaller.start()
                signaller.join(TimeUnit.SECONDS.toMillis(5))
                check(!signaller.isAlive) { "the shutdown signal waited on the launched work" }
                try { Thread.sleep(TimeUnit.SECONDS.toMillis(5)) } catch (cancelled: InterruptedException) {
                    interrupted.set(true)
                    throw cancelled
                }
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.deferred = true
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            try { f.pending.remove().run() } finally { Thread.interrupted() }
            assertTrue(interrupted.get(), "shutdown must observe the granted permit and interrupt its holder")
            assertContentEquals(CONTINUATION_BYTES, f.restored.single())
            assertEquals(WorkflowRunState.INTERRUPTED, f.attempt(successor).state)
            assertNull(f.attempt(successor).candidate)
        }
    }

    @Test
    fun `a launched continuation that waits for cancellation does not hold the service monitor`() {
        val interrupted = java.util.concurrent.atomic.AtomicBoolean()
        lateinit var fixture: Fixture
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            duringLaunch = {
                val running = fixture.snapshot().latestRun!!
                val cancel = java.util.concurrent.FutureTask {
                    fixture.service.cancelDurable(fixture.job.id, running.runId, running.version)
                }
                Thread(cancel, "launched-continuation-cancel").start()
                assertEquals(WorkflowRunState.CANCELLING, cancel.get(5, TimeUnit.SECONDS).state)
                try { Thread.sleep(TimeUnit.SECONDS.toMillis(5)) } catch (cancelled: InterruptedException) {
                    interrupted.set(true)
                    throw cancelled
                }
            }).use { f ->
            fixture = f
            val predecessor = f.start()
            f.deferred = true
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            try { f.pending.remove().run() } finally { Thread.interrupted() }
            assertTrue(interrupted.get())
            assertEquals(WorkflowRunState.CANCELLED, f.attempt(successor).state)
            assertEquals(WorkflowTerminalReason.CANCELLED, f.attempt(successor).terminalReason)
            assertNull(f.attempt(successor).candidate)
        }
    }

    @Test
    fun `matching bytes cannot substitute a different restoration mode`() {
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.AGENT_SESSION) }).use { f ->
            val predecessor = f.start()
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            assertEquals(WorkflowTerminalReason.REFUSED, f.attempt(successor).terminalReason)
            assertEquals(1, f.contexts.size)
            assertTrue(f.restored.isEmpty())
        }
    }

    @Test
    fun `continuation consumes detached bytes when predecessor changes after capture`() {
        val buffer = CONTINUATION_BYTES.copyOf()
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.PROJECT_EVIDENCE) },
            captureBytes = { request ->
                request.predecessorReportsDirectory.resolve("checkpoint").readBytes().copyInto(buffer)
                buffer
            },
            afterCapture = { request ->
                buffer.fill(0)
                Files.writeString(request.predecessorReportsDirectory.resolve("checkpoint"), "later contents")
            }).use { f ->
            val predecessor = f.start()
            val checkpoint = Files.write(f.contexts.single().reportsDirectory.resolve("checkpoint"), CONTINUATION_BYTES)
            f.outcomes += DurableWebWorkflowOutcome.Completed()
            val successor = run(f.recover(predecessor, mode = "resume")).getValue("runId").jsonPrimitive.content
            assertEquals(WorkflowRunState.COMPLETED, f.attempt(successor).state)
            assertEquals("later contents", Files.readString(checkpoint))
            assertContentEquals(CONTINUATION_BYTES, f.restored.single())
        }
    }

    @Test
    fun `resume refuses a predecessor recorded under a different harness`() {
        Fixture(checkpoints = { DurableWebWorkflowCheckpoint.Verified(SHA, WorkflowResumeRestoration.AGENT_SESSION) }, seed = { store, job ->
            val version = (store.inspect(job) as WorkflowJobInspection.Available).snapshot.version
            val created = store.create(job, version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, harnessCapabilityId = "older_harness")).attempt
            val started = store.transition(job, created.runId, created.version, WorkflowTransition.Start).attempt
            store.transition(job, started.runId, started.version, WorkflowTransition.Finish(WorkflowRunState.INTERRUPTED, WorkflowTerminalReason.PROCESS_INTERRUPTED))
        }).use { f ->
            val predecessor = f.snapshot().attempts.single().runId
            assertEquals(control(false, "HARNESS_CHANGED"), f.controls(predecessor).second.getValue("resume"))
            error(f.recover(predecessor, mode = "resume"), 409, "HARNESS_CHANGED")
            // An explicit retry is a fresh attempt under the current registration, not a continuation.
            val retried = run(f.recover(predecessor, key = "http_recovery_retry_after_harness"))
            assertEquals(CAPABILITY, retried.getValue("harnessCapabilityId").jsonPrimitive.content)
        }
    }

    @Test
    fun `recovery never silently starts from an unverified or unexpected input revision`() = Fixture(seed = { store, job ->
        val version = (store.inspect(job) as WorkflowJobInspection.Available).snapshot.version
        val created = store.create(job, version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS, "unaccepted_revision", CAPABILITY)).attempt
        val started = store.transition(job, created.runId, created.version, WorkflowTransition.Start).attempt
        store.transition(job, started.runId, started.version, WorkflowTransition.Finish(WorkflowRunState.FAILED, WorkflowTerminalReason.FAILED))
    }).use { f ->
        val predecessor = f.snapshot().attempts.single().runId
        val controls = f.controls(predecessor).second
        assertEquals("unaccepted_revision", controls.getValue("inputRevisionId").jsonPrimitive.content)
        assertEquals(control(false, "INPUT_UNVERIFIED"), controls.getValue("retry"))
        error(f.recover(predecessor, input = "unaccepted_revision"), 409, "INPUT_UNVERIFIED")
        error(f.recover(predecessor, key = "http_recovery_input_key_2"), 409, "INPUT_REVISION_CONFLICT")
        assertEquals(1, f.snapshot().attempts.size); assertTrue(f.contexts.isEmpty())
    }

    @Test
    fun `closed strict body and shared mutation boundary refuse before any body or service effect`() = Fixture().use { f ->
        val failed = f.start(); val version = f.attempt(failed).version
        val valid = f.mutation(version, KEY)
        val cases = listOf(
            (valid - "Cookie") to 401, (valid - "X-CSRF-Token") to 403, (valid + ("Origin" to "http://foreign.invalid")) to 403,
            (valid + ("Content-Type" to "text/plain")) to 415, (valid - "If-Match") to 428, (valid + ("If-Match" to "W/\"weak\"")) to 400,
            (valid - "Idempotency-Key") to 400, (valid + ("If-None-Match" to "*")) to 400, (valid + ("Accept" to "text/plain")) to 406,
            (valid + ("Content-Length" to "1025")) to 413,
        )
        for ((headers, status) in cases) {
            val exchange = f.memory(failed, recoverBody("retry", null).toByteArray(), headers); assertTrue(f.api.route(exchange))
            assertEquals(status, exchange.responseCode, exchange.output.toString()); assertEquals(0, exchange.input.bytesRead)
        }
        val body = recoverBody("retry", null)
        listOf("{}", "[]", recoverBody("restart", null), body.replace("{", "{\"workspacePath\":\"/private\","),
            body.replace("{", "{\"harnessCapabilityId\":\"$CAPABILITY\","), body.replace("null", "\"../private\""),
            body.replace("null", "17"), "{\"apiVersion\":1,\"kind\":\"recoverRequest\",\"data\":$body}",
        ).forEach { error(f.recover(failed, body = it), 422, "VALIDATION_FAILED") }
        error(f.recover(failed, body = body.replace("{", "{\"mode\":\"resume\",")), 400, "MALFORMED_JSON")
        val over = f.memory(failed, " ".repeat(4096).toByteArray(), valid); f.api.route(over)
        assertEquals(413, over.responseCode); assertEquals(1025, over.input.bytesRead)
        error(f.send(body = body, headers = valid, target = "${f.runs}/$failed/recover?mode=resume"), 400, "VALIDATION_FAILED")
        error(f.recover("missing_attempt", version = version), 404, "NOT_FOUND")
        assertEquals(1, f.snapshot().attempts.size); assertEquals(1, f.contexts.size)
    }

    @Test
    fun `cancel then retry reconciles the cancelled attempt before linking a new one`() = Fixture(deferred = true).use { f ->
        val queued = f.start()
        val active = f.controls(queued).second
        assertEquals(control(true, null), active.getValue("cancel"))
        assertEquals(control(false, "ATTEMPT_ACTIVE"), active.getValue("retry"))
        val cancel = f.send(body = "{\"action\":\"cancel\"}", headers = f.mutation(f.attempt(queued).version, "http_recovery_cancel_key"),
            target = "${f.runs}/$queued/cancel")
        assertEquals(202, cancel.statusCode(), cancel.body())
        assertEquals(WorkflowRunState.CANCELLED, f.attempt(queued).state)
        val cancelled = f.controls(queued).second
        assertEquals(control(false, "ATTEMPT_TERMINAL"), cancelled.getValue("cancel"))
        assertEquals(control(true, null), cancelled.getValue("retry"))
        val retried = run(f.recover(queued))
        assertEquals("queued", retried.getValue("state").jsonPrimitive.content)
        val successor = retried.getValue("runId").jsonPrimitive.content
        assertEquals(control(true, null), f.controls(successor).second.getValue("cancel"))
        // A command addressed to the predecessor cannot act on its successor.
        val old = f.send(body = "{\"action\":\"cancel\"}", headers = f.mutation(f.attempt(queued).version, "http_recovery_cancel_old"),
            target = "${f.runs}/$queued/cancel")
        assertEquals(200, old.statusCode(), old.body())
        assertEquals(WorkflowRunState.QUEUED, f.attempt(successor).state)
        assertEquals(0, f.contexts.size)
    }

    @Test
    fun `restart with registrations removed keeps keyed replay and refuses fresh recovery`() {
        val root = createTempDirectory("web-recovery-restart-")
        lateinit var jobId: String; lateinit var failed: String; lateinit var version: String; lateinit var retried: String
        try {
            Fixture(root = root, deleteRoot = false).use { f ->
                jobId = f.job.id; failed = f.start(); version = f.attempt(failed).version
                f.deferred = true
                retried = run(f.recover(failed)).getValue("runId").jsonPrimitive.content
                assertEquals(1, f.pending.size)
            }
            Fixture(root = root, reuseJob = jobId, registered = false, deleteRoot = false).use { f ->
                val before = f.state().readBytes()
                val replay = f.recover(failed, version = version)
                assertEquals(retried, run(replay).getValue("runId").jsonPrimitive.content)
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
                assertContentEquals(before, f.state().readBytes()); assertTrue(f.contexts.isEmpty())
                // Shutdown interrupted the queued retry; recovering it again needs a registered workflow.
                assertEquals(WorkflowRunState.INTERRUPTED, f.attempt(retried).state)
                assertEquals(control(false, "WORKFLOW_UNAVAILABLE"), f.controls(retried).second.getValue("retry"))
                error(f.recover(retried, key = "http_recovery_after_restart"), 503, "CAPABILITY_UNAVAILABLE")
                assertEquals(2, f.snapshot().attempts.size)
            }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `uncertain recovery publication never reports success or schedules work`() {
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC, WorkflowStoreFaultPoint.AFTER_RENAME)) Fixture().use { f ->
            val failed = f.start(); val version = f.attempt(failed).version
            f.fault = point
            error(f.recover(failed, version = version), 503, if (point == WorkflowStoreFaultPoint.AFTER_RENAME) "RECOVERY_REQUIRED" else "PERSISTENCE_FAILED")
            f.fault = null
            assertEquals(1, f.contexts.size)
            if (point == WorkflowStoreFaultPoint.AFTER_RENAME) error(f.recover(failed, version = version), 503, "RECOVERY_REQUIRED")
            else assertEquals(1, f.snapshot().attempts.size)
        }
    }

    @Test
    fun `without registrations or retained receipts the route is unavailable without consuming the body`() = Fixture(registered = false).use { f ->
        val exchange = f.memory("run_absent", recoverBody("retry", null).toByteArray(), f.mutation("run_version", KEY))
        f.api.route(exchange)
        assertEquals(503, exchange.responseCode); assertEquals(0, exchange.input.bytesRead)
        assertFalse(Files.exists(f.state()))
    }

    private fun control(available: Boolean, reason: String?) = buildJsonObject {
        put("available", available); put("reason", reason?.let(::JsonPrimitive) ?: JsonNull)
    }
    private fun run(response: HttpResponse<String>): JsonObject {
        assertEquals(202, response.statusCode(), response.body()); assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
        val document = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals("run", document.getValue("kind").jsonPrimitive.content)
        val run = document.getValue("data").jsonObject
        assertEquals("\"${run.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
        assertFalse(response.body().contains("PRIVATE_RECOVERY_")); return run
    }
    private fun error(response: HttpResponse<String>, status: Int, code: String) {
        assertEquals(status, response.statusCode(), response.body())
        assertEquals(code, Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        assertFalse(response.body().contains("PRIVATE_RECOVERY_")); assertTrue(response.headers().firstValue("Location").isEmpty)
    }
    private class ObservedInput(bytes: ByteArray) : InputStream() {
        private val source = ByteArrayInputStream(bytes)
        var bytesRead = 0
        override fun read(): Int = source.read().also { if (it >= 0) bytesRead++ }
        override fun read(target: ByteArray, offset: Int, length: Int): Int = source.read(target, offset, length).also { if (it > 0) bytesRead += it }
        override fun readNBytes(length: Int): ByteArray = source.readNBytes(length).also { bytesRead += it.size }
    }
    private class MemoryExchange(private val method: String, path: String, val input: ObservedInput, private val port: Int) : HttpExchange() {
        private val incoming = Headers(); private val outgoing = Headers(); val output = ByteArrayOutputStream(); private var status = -1
        private val uri = URI.create(path)
        override fun getRequestHeaders(): Headers = incoming
        override fun getResponseHeaders(): Headers = outgoing
        override fun getRequestURI(): URI = uri
        override fun getRequestMethod(): String = method
        override fun getHttpContext(): HttpContext = throw UnsupportedOperationException()
        override fun close() = Unit
        override fun getRequestBody(): InputStream = input
        override fun getResponseBody(): OutputStream = output
        override fun sendResponseHeaders(code: Int, length: Long) { status = code }
        override fun getRemoteAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", 1)
        override fun getResponseCode(): Int = status
        override fun getLocalAddress(): InetSocketAddress = InetSocketAddress("127.0.0.1", port)
        override fun getProtocol(): String = "HTTP/1.1"
        override fun getAttribute(name: String): Any? = null
        override fun setAttribute(name: String, value: Any?) = Unit
        override fun setStreams(input: InputStream?, output: OutputStream?) = Unit
        override fun getPrincipal(): HttpPrincipal? = null
    }
    private companion object {
        const val CAPABILITY = "authored_harness"
        const val KEY = "http_recovery_request_key_1"
        val CONTINUATION_BYTES = "verified inert checkpoint".toByteArray()
        val SHA = java.security.MessageDigest.getInstance("SHA-256").digest(CONTINUATION_BYTES).joinToString("") { "%02x".format(it) }
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)
        fun recoverBody(mode: String, input: String?) = buildJsonObject {
            put("mode", mode); put("expectedInputRevisionId", input?.let(::JsonPrimitive) ?: JsonNull)
        }.toString()
    }
}
