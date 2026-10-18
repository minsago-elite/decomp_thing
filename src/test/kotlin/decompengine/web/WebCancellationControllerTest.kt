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
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.readBytes
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class WebCancellationControllerTest {
    private class Fixture(
        preserveAccepted: Boolean = false,
        private val execute: () -> DurableWebWorkflowOutcome = {
            DurableWebWorkflowOutcome.Completed(WorkflowCandidate("candidate_authored", "a".repeat(64)))
        },
    ) : AutoCloseable {
        val root: Path = createTempDirectory("web-cancellation-http-")
        val store = JobStore(root)
        val job = store.createFromUpload("authored.elf", elfFixture())
        val prior = if (preserveAccepted) seedAccepted() else null
        val diagnostic = prior?.let {
            store.runReportsDirectory(job.id, it.runId, create = true).resolve("diagnostic.txt").also { path ->
                Files.writeString(path, "Retained inert HTTP diagnostic")
            }
        }
        val diagnosticBytes = diagnostic?.readBytes()
        val calls = AtomicInteger()
        val pending = ConcurrentLinkedQueue<Runnable>()
        @Volatile var fault: WorkflowStoreFaultPoint? = null
        var service = newService(registered = true)
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin, basePath = BASE))
        private val resources = WebStreamResources()
        private val workers = Executors.newFixedThreadPool(4)
        val client = HttpClient.newHttpClient()
        @Volatile var api = controller()
        val credentials: Credentials

        init {
            service.initializeExistingStorage()
            server.executor = workers
            server.createContext("/") { check(api.route(it)) }
            server.start()
            credentials = login()
        }

        private fun newService(registered: Boolean) = WebJobService(store,
            JobAnalyzer { _, _ -> error("PRIVATE_CANCEL_ANALYZER_FALLBACK") },
            JobReconstructor { _, _ -> error("PRIVATE_CANCEL_RECONSTRUCTOR_FALLBACK") },
            Executor { pending += it },
            durableAdapters = if (!registered) emptyList() else listOf(object : DurableWebWorkflowAdapter {
                override val workflow = WorkflowKind.RECONSTRUCT
                override val limits = LIMITS
                override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
                    calls.incrementAndGet()
                    return this@Fixture.execute()
                }
            }), attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC(), WorkflowStoreFaultInjector { point ->
                if (point == fault) throw IOException("PRIVATE_CANCEL_PUBLICATION_CANARY")
            }) })

        private fun controller() = WebApiController(access, EmbeddedWebAssets.load(basePath = BASE), service,
            WebJobMutationBoundary(access, service), resources)

        fun restartWithoutAdapters() {
            service.close()
            service = newService(registered = false)
            service.initializeExistingStorage()
            api = controller()
        }

        fun login(): Credentials {
            val response = send("${BASE}api/v1/session", "POST", "{\"token\":\"${access.issueBootstrap().token}\"}",
                mapOf("Origin" to origin, "Content-Type" to "application/json"))
            check(response.statusCode() == 200)
            return Credentials(response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'),
                Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content)
        }

        fun headers(version: String, key: String = KEY, auth: Credentials = credentials) = mapOf(
            "Cookie" to auth.cookie, "Origin" to origin, "Content-Type" to "application/json",
            "X-CSRF-Token" to auth.csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key,
        )
        fun path(run: WorkflowAttempt) = "${BASE}api/v1/jobs/${run.jobId}/runs/${run.runId}/cancel"
        fun start(jobId: String = job.id, key: String = "http_cancel_start_key_1234"): WorkflowAttempt {
            val version = webJob(service.presentation(jobId)).getValue("version").jsonPrimitive.content
            return service.requestDurableStart(jobId, version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS), key).attempt
        }
        fun startOverHttp(): WorkflowAttempt {
            val version = webJob(service.presentation(job.id)).getValue("version").jsonPrimitive.content
            val body = """{"workflow":"reconstruct","inputRevisionId":null,"harnessCapabilityId":null,"limits":{"wallClockMs":"60000","idleMs":"15000","maxOutputBytes":"1048576","maxToolCalls":"16"}}"""
            val response = send("${BASE}api/v1/jobs/${job.id}/runs", headers = headers(version, "http_cancel_wire_start_key"), body = body)
            val value = run(response, 202)
            return service.getAttempt(job.id, value.getValue("runId").jsonPrimitive.content)
        }
        fun cancel(run: WorkflowAttempt, key: String = KEY, body: String = BODY,
            auth: Credentials = credentials) = send(path(run), headers = headers(run.version, key, auth), body = body)
        fun send(target: String, method: String = "POST", body: String? = BODY,
            headers: Map<String, String>): HttpResponse<String> {
            val request = HttpRequest.newBuilder(URI(origin + target)).timeout(Duration.ofSeconds(5)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofInputStream { it.byteInputStream() } } ?: HttpRequest.BodyPublishers.noBody())
            request.header("Accept", "application/json")
            headers.forEach { (key, value) -> request.header(key, value) }
            return client.send(request.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun memory(run: WorkflowAttempt, body: ByteArray = BODY.toByteArray(),
            headers: Map<String, String> = this.headers(run.version), target: String = path(run), method: String = "POST") =
            MemoryExchange(method, target, ObservedInput(body), server.address.port).apply {
                requestHeaders.set("Host", URI(origin).rawAuthority)
                requestHeaders.set("Accept", "application/json")
                headers.forEach { (key, value) -> requestHeaders.set(key, value) }
            }
        fun snapshot() = (service.inspectDurableJob(job.id) as WorkflowJobInspection.Available).snapshot
        fun state() = root.resolve(job.id).resolve("workflow-state.json")
        fun assertPriorPreserved() {
            val prior = checkNotNull(prior)
            assertEquals(prior.acceptedRevision, snapshot().acceptedRevision)
            assertEquals(prior, snapshot().attempts.single { it.runId == prior.runId })
            assertContentEquals(checkNotNull(diagnosticBytes), checkNotNull(diagnostic).readBytes())
        }
        private fun seedAccepted(): WorkflowAttempt = WorkflowAttemptStore.open(root).use { owner ->
            val queued = owner.create(job.id, (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot.version,
                NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, LIMITS))
            val started = owner.transition(job.id, queued.attempt.runId, queued.attempt.version, WorkflowTransition.Start)
            val completed = owner.transition(job.id, started.attempt.runId, started.attempt.version,
                WorkflowTransition.Finish(WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED,
                    WorkflowCandidate("revision_preserved", "b".repeat(64))))
            owner.recordAcceptedRevision(job.id, completed.attempt.runId, completed.snapshot.version, completed.attempt.version,
                WorkflowAcceptanceReference(job.id, completed.attempt.runId, "revision_preserved", "b".repeat(64),
                    "graph_authored", "artifact_authored", "c".repeat(64))).attempt
        }
        override fun close() {
            fault = null
            server.stop(0); resources.close(); workers.shutdownNow()
            check(workers.awaitTermination(5, TimeUnit.SECONDS))
            client.close(); access.close(); service.close()
            root.toFile().deleteRecursively()
        }
    }

    @Test fun `queued HTTP cancellation keeps original status and replay cannot dispatch a later pinned run`() = Fixture().use { f ->
        val original = f.startOverHttp()
        val first = f.cancel(original)
        val cancelled = run(first, 202)
        assertEquals("cancelled", cancelled.getValue("state").jsonPrimitive.content)
        assertTrue(first.headers().firstValue("Idempotency-Replayed").isEmpty)
        val current = f.service.getAttempt(f.job.id, original.runId)
        run(f.cancel(current, key = "http_cancel_terminal_fresh"), 200)
        val pinnedOld = f.service.setProgressRetentionPinned(f.job.id, original.runId, current.version, true)
        val later = f.start(key = "http_cancel_later_start_key")
        val pinnedLater = f.service.setProgressRetentionPinned(f.job.id, later.runId, later.version, true)
        val bytes = f.state().readBytes()
        val replay = f.cancel(original)
        val replayed = run(replay, 202)
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(pinnedOld.version, replayed.getValue("version").jsonPrimitive.content)
        error(f.cancel(pinnedOld), 409, "IDEMPOTENCY_CONFLICT")
        assertEquals(pinnedLater, f.service.getAttempt(f.job.id, later.runId))
        assertContentEquals(bytes, f.state().readBytes())
        assertEquals(2, f.pending.size)
        f.pending.remove().run()
        assertEquals(0, f.calls.get()); assertEquals(pinnedLater, f.service.getAttempt(f.job.id, later.runId))
        f.pending.remove().run()
        assertEquals(1, f.calls.get())
        val terminal = f.service.getAttempt(f.job.id, later.runId)
        assertEquals(WorkflowRunState.COMPLETED, terminal.state); assertTrue(terminal.progressRetentionPinned)
        assertNull(terminal.acceptedRevision)
    }

    @Test fun `concurrent running HTTP replay signals once and preserves accepted references through confirmed outcomes`() {
        for (completeDespiteCancel in listOf(false, true)) {
            val entered = CountDownLatch(1); val signalled = CountDownLatch(1); val release = CountDownLatch(1)
            val signals = AtomicInteger()
            val executor = Executors.newSingleThreadExecutor { runnable -> object : Thread(runnable) {
                override fun interrupt() { signals.incrementAndGet(); super.interrupt() }
            } }
            val requests = Executors.newFixedThreadPool(2)
            Fixture(preserveAccepted = true, execute = {
                entered.countDown()
                while (release.count != 0L) try { release.await() } catch (_: InterruptedException) { signalled.countDown() }
                if (!completeDespiteCancel) throw InterruptedException("owned cancellation")
                Thread.currentThread().interrupt()
                DurableWebWorkflowOutcome.Completed(WorkflowCandidate("candidate_after_cancel", "d".repeat(64)))
            }).use { f ->
                try {
                    val queued = f.start(); executor.execute(f.pending.remove())
                    assertTrue(entered.await(5, TimeUnit.SECONDS))
                    val running = f.service.getAttempt(f.job.id, queued.runId)
                    val beforeSignals = signals.get()
                    val replies = List(2) { requests.submit<HttpResponse<String>> { f.cancel(running) } }
                        .map { it.get(5, TimeUnit.SECONDS) }
                    replies.forEach { assertEquals("cancelling", run(it, 202).getValue("state").jsonPrimitive.content) }
                    assertEquals(1, replies.count { it.headers().firstValue("Idempotency-Replayed").orElse("") == "true" })
                    assertEquals(beforeSignals + 1, signals.get()); assertTrue(signalled.await(5, TimeUnit.SECONDS))
                    val pending = f.service.getAttempt(f.job.id, running.runId)
                    assertEquals(WorkflowRunState.CANCELLING, pending.state); assertNull(pending.endedAt)
                    f.assertPriorPreserved()
                    val pinned = f.service.setProgressRetentionPinned(f.job.id, pending.runId, pending.version, true)
                    val bytes = f.state().readBytes()
                    assertEquals(pinned.version, run(f.cancel(running), 202).getValue("version").jsonPrimitive.content)
                    error(f.cancel(running, key = "http_cancel_fresh_stale_key"), 412, "VERSION_CONFLICT")
                    assertEquals(beforeSignals + 1, signals.get()); assertContentEquals(bytes, f.state().readBytes())
                    release.countDown(); executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
                    val ended = run(f.cancel(running), 202)
                    assertEquals(if (completeDespiteCancel) "completed" else "cancelled", ended.getValue("state").jsonPrimitive.content)
                    val terminal = f.service.getAttempt(f.job.id, running.runId)
                    assertTrue(terminal.progressRetentionPinned); assertNull(terminal.acceptedRevision)
                    f.assertPriorPreserved()
                    val later = f.start(key = "http_cancel_post_race_start")
                    val next = f.service.setProgressRetentionPinned(f.job.id, later.runId, later.version, true)
                    val beforeReplay = f.state().readBytes()
                    run(f.cancel(running), 202)
                    assertEquals(next, f.service.getAttempt(f.job.id, later.runId))
                    assertContentEquals(beforeReplay, f.state().readBytes()); f.assertPriorPreserved()
                    // Reopen service/storage under the same listener authorization service.
                    f.restartWithoutAdapters()
                    val recovered = f.state().readBytes()
                    run(f.cancel(running), 202)
                    f.pending.remove().run()
                    assertContentEquals(recovered, f.state().readBytes()); f.assertPriorPreserved()
                    assertEquals(1, f.calls.get())
                } finally {
                    release.countDown(); executor.shutdownNow(); requests.shutdownNow()
                    assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)); assertTrue(requests.awaitTermination(5, TimeUnit.SECONDS))
                }
            }
        }
    }

    @Test fun `fresh terminal HTTP intent returns200 and never grants acceptance or executes again`() = Fixture().use { f ->
        val queued = f.start(); f.pending.remove().run()
        val terminal = f.service.getAttempt(f.job.id, queued.runId)
        error(f.cancel(queued), 412, "VERSION_CONFLICT")
        val first = run(f.cancel(terminal), 200)
        assertEquals("completed", first.getValue("state").jsonPrimitive.content)
        assertEquals("not-evaluated", first.getValue("acceptance").jsonPrimitive.content)
        val before = f.state().readBytes()
        val replay = f.cancel(terminal)
        assertEquals(first, run(replay, 200)); assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertContentEquals(before, f.state().readBytes()); assertEquals(1, f.calls.get()); assertNull(f.snapshot().acceptedRevision)
    }

    @Test fun `authorization headers methods and canonical targets are refused before body consumption`() = Fixture().use { f ->
        val queued = f.start(); val valid = f.headers(queued.version); val before = f.state().readBytes()
        val cases = listOf((valid - "Cookie") to 401, (valid - "X-CSRF-Token") to 403,
            (valid + ("Origin" to "http://foreign.invalid")) to 403, (valid + ("Content-Type" to "text/plain")) to 415,
            (valid + ("X-Forwarded-Host" to "foreign.invalid")) to 403, (valid - "If-Match") to 428,
            (valid + ("If-Match" to "*")) to 400, (valid + ("If-Match" to "W/\"weak\"")) to 400,
            (valid - "Idempotency-Key") to 400, (valid + ("Idempotency-Key" to "short")) to 400,
            (valid + ("If-None-Match" to "*")) to 400, (valid + ("Accept" to "text/plain")) to 406,
            (valid + ("Content-Length" to "1025")) to 413, (valid + ("Content-Length" to "01")) to 400)
        for ((headers, status) in cases) {
            val exchange = f.memory(queued, headers = headers); f.api.route(exchange)
            assertEquals(status, exchange.responseCode, exchange.output.toString()); assertEquals(0, exchange.input.bytesRead)
        }
        for (header in listOf("If-Match", "Idempotency-Key", "Content-Length")) {
            val exchange = f.memory(queued).apply { requestHeaders.add(header, if (header == "Content-Length") "1" else valid.getValue(header)) }
            if (header == "Content-Length") exchange.requestHeaders.add(header, "1")
            f.api.route(exchange); assertEquals(400, exchange.responseCode); assertEquals(0, exchange.input.bytesRead)
        }
        for ((target, status) in listOf((f.path(queued) + "?actor=selected") to 400,
            f.path(queued).replace(f.job.id, "%2e%2e") to 404, f.path(queued).replace(queued.runId, "%2e%2e") to 404)) {
            val exchange = f.memory(queued, target = target); f.api.route(exchange)
            assertEquals(status, exchange.responseCode); assertEquals(0, exchange.input.bytesRead)
        }
        for (method in listOf("GET", "HEAD", "PUT", "DELETE")) {
            val exchange = f.memory(queued, method = method); f.api.route(exchange)
            assertEquals(405, exchange.responseCode); assertEquals("POST", exchange.responseHeaders.getFirst("Allow"))
            assertEquals(0, exchange.input.bytesRead)
        }
        assertContentEquals(before, f.state().readBytes()); assertEquals(queued, f.service.getAttempt(f.job.id, queued.runId)); assertEquals(0, f.calls.get())
    }

    @Test fun `closed strict cancellation JSON rejects actors targets wrappers duplicate keys and oversized bytes`() = Fixture().use { f ->
        val queued = f.start(); val before = f.state().readBytes()
        for (body in listOf("{}", "[]", "{\"action\":false}", "{\"action\":\"terminate\"}",
            "{\"action\":\"cancel\",\"actor\":\"selected_actor\"}", "{\"action\":\"cancel\",\"runId\":\"other_run\"}",
            "{\"action\":\"cancel\",\"command\":\"private_command\"}",
            "{\"apiVersion\":1,\"kind\":\"workflowCancelRequest\",\"data\":$BODY}")) {
            error(f.cancel(queued, body = body), 422, "VALIDATION_FAILED")
        }
        error(f.cancel(queued, body = "{\"action\":\"cancel\",\"action\":\"cancel\"}"), 400, "MALFORMED_JSON")
        val malformed = f.memory(queued, body = byteArrayOf(0xc3.toByte(), 0x28)); f.api.route(malformed)
        assertEquals(400, malformed.responseCode)
        val oversized = f.memory(queued, body = " ".repeat(4096).toByteArray()); f.api.route(oversized)
        assertEquals(413, oversized.responseCode); assertEquals(1025, oversized.input.bytesRead)
        assertContentEquals(before, f.state().readBytes()); assertEquals(queued, f.service.getAttempt(f.job.id, queued.runId))
        run(f.cancel(queued, body = " ".repeat(1024 - BODY.length) + BODY), 202)
        assertEquals(0, f.calls.get())
    }

    @Test fun `missing foreign and stale HTTP targets cannot cancel either owned attempt`() = Fixture().use { f ->
        val queued = f.start()
        val other = f.store.createFromUpload("other.elf", elfFixture()); val foreign = f.start(other.id, "http_cancel_foreign_start")
        val ownBytes = f.state().readBytes(); val otherPath = f.root.resolve("${other.id}/workflow-state.json"); val otherBytes = otherPath.readBytes()
        error(f.send(f.path(queued).replace(f.job.id, "f".repeat(32)), headers = f.headers(queued.version)), 404, "NOT_FOUND")
        error(f.send(f.path(queued).replace(queued.runId, foreign.runId), headers = f.headers(queued.version)), 404, "NOT_FOUND")
        error(f.send(f.path(queued).replace(queued.runId, "run_missing"), headers = f.headers(queued.version)), 404, "NOT_FOUND")
        error(f.send(f.path(queued), headers = f.headers("version_stale")), 412, "VERSION_CONFLICT")
        assertEquals(queued, f.service.getAttempt(f.job.id, queued.runId)); assertEquals(foreign, f.service.getAttempt(other.id, foreign.runId))
        assertContentEquals(ownBytes, f.state().readBytes()); assertContentEquals(otherBytes, otherPath.readBytes()); assertEquals(0, f.calls.get())
    }

    @Test fun `authenticated actors cannot replay each other and revoked sessions cannot retrieve receipts`() = Fixture().use { f ->
        val queued = f.start(); run(f.cancel(queued), 202)
        val before = f.state().readBytes(); val other = f.login()
        error(f.cancel(queued, auth = other), 412, "VERSION_CONFLICT")
        val original = f.cancel(queued); run(original, 202)
        assertEquals("true", original.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertContentEquals(before, f.state().readBytes()); assertEquals(1, f.snapshot().cancellationReceipts.entries.size)
        val logout = f.send("${BASE}api/v1/session", "DELETE", null, mapOf("Cookie" to f.credentials.cookie,
            "Origin" to f.origin, "Content-Type" to "application/json", "X-CSRF-Token" to f.credentials.csrf))
        assertEquals(204, logout.statusCode())
        val denied = f.memory(queued); f.api.route(denied)
        assertEquals(401, denied.responseCode); assertEquals(0, denied.input.bytesRead)
        assertContentEquals(before, f.state().readBytes())
        val terminal = f.service.getAttempt(f.job.id, queued.runId)
        run(f.cancel(terminal, auth = other), 200)
        assertEquals(2, f.snapshot().cancellationReceipts.entries.size); assertEquals(0, f.calls.get())
    }

    @Test fun `HTTP receipt capacity refuses new intent while the original acknowledgement remains replayable`() = Fixture().use { f ->
        val queued = f.start(); run(f.cancel(queued), 202)
        val terminal = f.service.getAttempt(f.job.id, queued.runId)
        val authorization = checkNotNull(f.access.authorize(f.memory(terminal, method = "GET"), WebEndpointPolicy.privateRead()))
        val actor = WorkflowCancellationActor.browserSession(authorization.sessionId)
        // Seed bounded storage through the trusted service; exercise admission/refusal over HTTP.
        for (index in 1 until WorkflowCancellationReceipts.MAX_ENTRIES) {
            f.service.requestDurableCancellation(f.job.id, terminal.runId, terminal.version, actor, "http_cancel_capacity_$index")
        }
        val before = f.state().readBytes()
        error(f.cancel(terminal, key = "http_cancel_over_capacity"), 429, "CANCELLATION_RECEIPT_CAPACITY")
        val replay = f.cancel(queued); run(replay, 202)
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(WorkflowCancellationReceipts.MAX_ENTRIES, f.snapshot().cancellationReceipts.entries.size)
        assertContentEquals(before, f.state().readBytes()); assertEquals(0, f.calls.get())
    }

    @Test fun `known unchanged publication failures return no HTTP acknowledgement and do not suppress dispatch`() {
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_WRITE, WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC)) Fixture().use { f ->
            val queued = f.start(); val before = f.state().readBytes(); f.fault = point
            error(f.cancel(queued), 503, "PERSISTENCE_FAILED")
            assertContentEquals(before, f.state().readBytes()); assertEquals(queued, f.service.getAttempt(f.job.id, queued.runId))
            assertTrue(f.snapshot().cancellationReceipts.entries.isEmpty()); assertEquals(0, f.calls.get())
            f.fault = null; f.pending.remove().run()
            assertEquals(1, f.calls.get()); assertEquals(WorkflowRunState.COMPLETED, f.service.getAttempt(f.job.id, queued.runId).state)
        }
    }

    @Test fun `uncertain publication refuses HTTP success and reopens without dispatch under retained listener authorization`() {
        for (point in listOf(WorkflowStoreFaultPoint.BEFORE_RENAME, WorkflowStoreFaultPoint.AFTER_RENAME)) Fixture().use { f ->
            val queued = f.start(); f.fault = point
            error(f.cancel(queued), 503, "RECOVERY_REQUIRED")
            val uncertain = f.state().readBytes(); f.pending.remove().run()
            assertEquals(0, f.calls.get()); assertContentEquals(uncertain, f.state().readBytes())
            error(f.cancel(queued), 503, "RECOVERY_REQUIRED")
            f.fault = null; f.restartWithoutAdapters()
            val recovered = f.state().readBytes()
            if (point == WorkflowStoreFaultPoint.AFTER_RENAME) {
                val replay = f.cancel(queued); assertEquals("interrupted", run(replay, 202).getValue("state").jsonPrimitive.content)
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
            } else {
                error(f.cancel(queued), 412, "VERSION_CONFLICT")
                assertTrue(f.snapshot().cancellationReceipts.entries.isEmpty())
            }
            assertContentEquals(recovered, f.state().readBytes()); assertTrue(f.pending.isEmpty()); assertEquals(0, f.calls.get())
        }
    }

    @Test fun `terminal HTTP intent without registrations does not enable starts or advertise production readiness`() = Fixture().use { f ->
        val initialVersion = webJob(f.service.presentation(f.job.id)).getValue("version").jsonPrimitive.content
        val admitted = assertIs<DurableWebWorkflowAdmission.Started>(f.service.startDurable(f.job.id, initialVersion,
            DurableWebWorkflowRequest(WorkflowKind.RECONSTRUCT)))
        val queued = f.service.getAttempt(f.job.id, admitted.runId)
        f.pending.remove().run(); f.restartWithoutAdapters()
        val terminal = f.service.getAttempt(f.job.id, queued.runId)
        assertEquals("completed", run(f.cancel(terminal), 200).getValue("state").jsonPrimitive.content)
        val bootstrap = f.send("${BASE}api/v1/bootstrap", "GET", null, mapOf("Cookie" to f.credentials.cookie))
        assertEquals(200, bootstrap.statusCode()); assertTrue(bootstrap.body().contains("PREVIEW_UNAVAILABLE"))
        val version = webJob(f.service.presentation(f.job.id)).getValue("version").jsonPrimitive.content
        // No registered adapter and no keyed-start receipt: preserve the existing start-route 405.
        val startBody = """{"workflow":"reconstruct","inputRevisionId":null,"harnessCapabilityId":null,"limits":{"wallClockMs":"60000","idleMs":"15000","maxOutputBytes":"1048576","maxToolCalls":"16"}}"""
        val response = f.send("${BASE}api/v1/jobs/${f.job.id}/runs", body = startBody,
            headers = f.headers(version, "http_cancel_unavailable_start"))
        error(response, 405, "METHOD_NOT_ALLOWED")
        assertEquals(1, f.calls.get()); assertTrue(f.pending.isEmpty()); assertNull(f.snapshot().acceptedRevision)
    }

    private data class Credentials(val cookie: String, val csrf: String)

    private companion object {
        const val BASE = "/workbench/"
        const val KEY = "http_cancel_request_key_1234"
        const val BODY = "{\"action\":\"cancel\"}"
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)

        fun run(response: HttpResponse<String>, status: Int): JsonObject {
            assertEquals(status, response.statusCode(), response.body())
            assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
            val document = Json.parseToJsonElement(response.body()).jsonObject
            assertEquals("run", document.getValue("kind").jsonPrimitive.content)
            assertEquals(document.getValue("requestId").jsonPrimitive.content, response.headers().firstValue("X-Request-ID").orElseThrow())
            val value = document.getValue("data").jsonObject
            assertEquals("\"${value.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
            assertEquals("${BASE}api/v1/jobs/${value.getValue("jobId").jsonPrimitive.content}/runs/${value.getValue("runId").jsonPrimitive.content}",
                response.headers().firstValue("Location").orElseThrow())
            assertFalse(response.body().contains("PRIVATE_CANCEL_")); assertFalse(response.body().contains("actorDigest"))
            assertFalse(response.body().contains("requestKeyDigest")); assertFalse(response.body().contains("acknowledgement"))
            return value
        }
        fun error(response: HttpResponse<String>, status: Int, code: String) {
            assertEquals(status, response.statusCode(), response.body())
            assertEquals(code, Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
            assertTrue(response.headers().firstValue("Location").isEmpty); assertTrue(response.headers().firstValue("ETag").isEmpty)
            assertFalse(response.body().contains("PRIVATE_CANCEL_")); assertFalse(response.body().contains("requestKeyDigest"))
        }
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
}
