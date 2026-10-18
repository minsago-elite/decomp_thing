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
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.readBytes
import kotlin.test.*

@ExtendWith(RecoveryMatrixEvidence::class)
class WebWorkflowStartControllerTest {
    private class Fixture(
        val root: Path = createTempDirectory("web-workflow-start-http-"),
        reuseJob: String? = null,
        registered: Boolean = true,
        deferred: Boolean = false,
        val limits: WorkflowExecutionLimits = LIMITS,
        val capability: String? = CAPABILITY,
        val scheduleFailure: RuntimeException? = null,
        private val deleteRoot: Boolean = true,
    ) : AutoCloseable {
        val store = JobStore(root)
        val job = reuseJob?.let(store::get) ?: store.createFromUpload("authored.elf", elfFixture())
        val calls = AtomicInteger()
        val pending = ConcurrentLinkedQueue<Runnable>()
        @Volatile var fault: WorkflowStoreFaultPoint? = null
        val service = WebJobService(store,
            JobAnalyzer { _, _ -> error("PRIVATE_START_ANALYZER_FALLBACK") },
            JobReconstructor { _, _ -> error("PRIVATE_START_RECONSTRUCTOR_FALLBACK") },
            Executor { task ->
                if (scheduleFailure != null) { pending.add(task); throw scheduleFailure }
                if (deferred) pending.add(task) else task.run()
            }, workers = 1, queueCapacity = 1,
            durableAdapters = if (!registered) emptyList() else listOf(object : DurableWebWorkflowAdapter {
                override val workflow = WorkflowKind.RECONSTRUCT
                override val limits = this@Fixture.limits
                override val harnessCapabilityId = capability
                override fun execute(context: DurableWebWorkflowContext): DurableWebWorkflowOutcome {
                    check(context.attempt.harnessCapabilityId == capability)
                    calls.incrementAndGet()
                    return DurableWebWorkflowOutcome.Completed(WorkflowCandidate("candidate_authored", "a".repeat(64)))
                }
            }), attemptStoreFactory = { WorkflowAttemptStore.open(it, Clock.systemUTC(), WorkflowStoreFaultInjector { point ->
                if (point == fault) throw IOException("PRIVATE_START_PERSISTENCE_CANARY")
            }) })
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${server.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources()
        val workers = Executors.newFixedThreadPool(2)
        val client = HttpClient.newHttpClient()
        val api = WebApiController(access, EmbeddedWebAssets.load(basePath = "/workbench/"), service,
            WebJobMutationBoundary(access, service), resources)
        val path = "/workbench/api/v1/jobs/${job.id}/runs"
        val cookie: String
        val csrf: String
        init {
            service.initializeExistingStorage()
            server.executor = workers; server.createContext("/") { check(api.route(it)) }; server.start()
            val session = send("POST", "{\"token\":\"${access.issueBootstrap().token}\"}",
                mapOf("Origin" to origin, "Content-Type" to "application/json"), "/workbench/api/v1/session")
            check(session.statusCode() == 200)
            cookie = session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            csrf = Json.parseToJsonElement(session.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        }
        fun version(jobId: String = job.id) = webJob(service.presentation(jobId)).getValue("version").jsonPrimitive.content
        fun headers(version: String = this.version(), key: String = KEY) = mapOf("Cookie" to cookie, "Origin" to origin,
            "Content-Type" to "application/json", "X-CSRF-Token" to csrf, "If-Match" to "\"$version\"", "Idempotency-Key" to key)
        fun body() = buildJsonObject {
            put("workflow", "reconstruct"); put("inputRevisionId", JsonNull)
            put("harnessCapabilityId", capability?.let(::JsonPrimitive) ?: JsonNull)
            put("limits", buildJsonObject {
                put("wallClockMs", limits.wallClockMs.toString()); put("idleMs", limits.idleMs.toString())
                put("maxOutputBytes", limits.maxOutputBytes.toString()); put("maxToolCalls", limits.maxToolCalls.toString())
            })
        }.toString()
        fun send(method: String = "POST", body: String? = this.body(), headers: Map<String, String> = this.headers(), target: String = path): HttpResponse<String> {
            val b = HttpRequest.newBuilder(URI(origin + target)).timeout(Duration.ofSeconds(5)).method(method,
                body?.let { HttpRequest.BodyPublishers.ofInputStream { it.byteInputStream() } } ?: HttpRequest.BodyPublishers.noBody())
            b.header("Accept", "application/json"); headers.forEach { (k, v) -> b.header(k, v) }
            return client.send(b.build(), HttpResponse.BodyHandlers.ofString()).also(::assertNoWebCors)
        }
        fun memory(body: ByteArray = this.body().toByteArray(), headers: Map<String, String> = this.headers(), target: String = path,
            method: String = "POST"): MemoryExchange = MemoryExchange(method, target, ObservedInput(body), server.address.port).apply {
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
    fun `real HTTP start and old keyed replay retain the original run without executing later work`() = Fixture().use { f ->
        val original = f.version()
        val response = f.send(headers = f.headers(original)); val first = run(response)
        val id = first.getValue("runId").jsonPrimitive.content
        assertEquals("completed", first.getValue("state").jsonPrimitive.content)
        assertEquals("not-evaluated", first.getValue("acceptance").jsonPrimitive.content)
        assertEquals(CAPABILITY, first.getValue("harnessCapabilityId").jsonPrimitive.content)
        assertEquals("${f.path}/$id", response.headers().firstValue("Location").orElseThrow())
        val later = run(f.send(headers = f.headers(key = "http_start_second_key")))
        assertNotEquals(id, later.getValue("runId").jsonPrimitive.content)
        val before = f.state().readBytes()
        val replay = f.send(body = " \n${f.body()} ", headers = f.headers(original))
        assertEquals(first, run(replay)); assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(response.headers().firstValue("Location"), replay.headers().firstValue("Location"))
        assertEquals(2, f.calls.get()); assertContentEquals(before, f.state().readBytes())
        assertNull(f.snapshot().acceptedRevision)
        error(f.send(body = f.body().replace("reconstruct", "validate"), headers = f.headers(original)), 409, "IDEMPOTENCY_CONFLICT")
        error(f.send(headers = f.headers(original, "http_start_fresh_stale")), 412, "VERSION_CONFLICT")
        val bootstrap = f.send("GET", null, mapOf("Cookie" to f.cookie), "/workbench/api/v1/bootstrap")
        assertEquals(200, bootstrap.statusCode()); assertTrue(bootstrap.body().contains("PREVIEW_UNAVAILABLE"))
    }

    @Test
    fun `queued replay per job exclusion and owned queue bounds have truthful HTTP results`() = Fixture(deferred = true).use { f ->
        val original = f.version(); val first = run(f.send(headers = f.headers(original)))
        assertEquals("queued", first.getValue("state").jsonPrimitive.content)
        val sameJob = f.send(headers = f.headers(key = "http_start_another_key")); error(sameJob, 409, "ACTIVE_RUN")
        val other = f.store.createFromUpload("other.elf", elfFixture())
        run(f.send(headers = f.headers(f.version(other.id), "http_start_other_job"), target = f.path.replace(f.job.id, other.id)))
        val third = f.store.createFromUpload("third.elf", elfFixture())
        error(f.send(headers = f.headers(f.version(third.id), "http_start_third_job"), target = f.path.replace(f.job.id, third.id)), 429, "QUOTA_EXCEEDED")
        assertTrue((f.service.inspectDurableJob(third.id) as WorkflowJobInspection.Available).snapshot.attempts.isEmpty())
        val replay = f.send(headers = f.headers(original)); assertEquals(first, run(replay))
        assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
        assertEquals(2, f.pending.size); assertEquals(0, f.calls.get())
        f.pending.remove().run()
        assertEquals(1, f.calls.get())
        assertEquals(WorkflowRunState.COMPLETED, f.service.getAttempt(f.job.id, first.getValue("runId").jsonPrimitive.content).state)
    }

    @Test
    fun `authorization header and target refusals never consume the body or admit work`() = Fixture().use { f ->
        val valid = f.headers()
        val cases = listOf(
            (valid - "Cookie") to 401, (valid - "X-CSRF-Token") to 403,
            (valid + ("Origin" to "http://foreign.invalid")) to 403,
            (valid + ("Content-Type" to "text/plain")) to 415,
            (valid + ("X-Forwarded-Host" to "foreign.invalid")) to 403,
            (valid - "If-Match") to 428, (valid + ("If-Match" to "*")) to 400,
            (valid + ("If-Match" to "W/\"weak\"")) to 400, (valid - "Idempotency-Key") to 400,
            (valid + ("If-None-Match" to "*")) to 400, (valid + ("Accept" to "text/plain")) to 406,
            (valid + ("Content-Length" to "4097")) to 413,
        )
        for ((headers, status) in cases) {
            val exchange = f.memory(headers = headers); assertTrue(f.api.route(exchange))
            assertEquals(status, exchange.responseCode, exchange.output.toString()); assertEquals(0, exchange.input.bytesRead)
        }
        for (header in listOf("If-Match", "Idempotency-Key", "Content-Length")) {
            val exchange = f.memory().apply { requestHeaders.add(header, if (header == "Content-Length") "1" else valid.getValue(header)) }
            // Content-Length was absent; add its second value explicitly.
            if (header == "Content-Length") exchange.requestHeaders.add(header, "1")
            f.api.route(exchange); assertEquals(400, exchange.responseCode); assertEquals(0, exchange.input.bytesRead)
        }
        for ((target, status) in listOf((f.path + "?command=private") to 400, f.path.replace(f.job.id, "%2e%2e") to 404)) {
            val exchange = f.memory(target = target); f.api.route(exchange)
            assertEquals(status, exchange.responseCode); assertEquals(0, exchange.input.bytesRead)
        }
        val wrongMethod = f.memory(method = "PUT"); f.api.route(wrongMethod)
        assertEquals(405, wrongMethod.responseCode); assertEquals(0, wrongMethod.input.bytesRead)
        assertTrue(f.snapshot().attempts.isEmpty()); assertFalse(Files.exists(f.state())); assertEquals(0, f.calls.get())
    }

    @Test
    fun `closed strict JSON and canonical unsigned limits cannot inject commands or paths`() = Fixture().use { f ->
        val body = f.body()
        val invalid = listOf("{}", "[]", body.replace("reconstruct", "execute"), body.replace("\"workflow\":", "\"extra\":null,\"workflow\":"),
            body.replace("\"inputRevisionId\":null", "\"inputRevisionId\":\"../private\""),
            body.replace("\"harnessCapabilityId\":\"$CAPABILITY\"", "\"harnessCapabilityId\":17"),
            body.replace("\"60000\"", "60000"), body.replace("\"60000\"", "\"060000\""),
            body.replace("\"60000\"", "\"-1\""), body.replace("\"60000\"", "\"18446744073709551616\""),
            body.replace("\"15000\"", "\"60001\""), body.replace("\"60000\"", "\"0\""),
            body.replace("\"16\"", "\"1e2\""), body.replace("\"limits\":{", "\"limits\":{\"command\":\"private\","),
            "{\"apiVersion\":1,\"kind\":\"workflowStartRequest\",\"data\":$body}")
        invalid.forEach { error(f.send(body = it), 422, "VALIDATION_FAILED") }
        error(f.send(body = body.replace("\"workflow\":", "\"workflow\":\"build\",\"workflow\":")), 400, "MALFORMED_JSON")
        val malformed = f.memory(body = byteArrayOf(0xc3.toByte(), 0x28)); f.api.route(malformed)
        assertEquals(400, malformed.responseCode)
        val over = f.memory(body = " ".repeat(8192).toByteArray()); f.api.route(over)
        assertEquals(413, over.responseCode); assertEquals(4097, over.input.bytesRead)
        assertTrue(f.snapshot().attempts.isEmpty()); assertFalse(Files.exists(f.state())); assertEquals(0, f.calls.get())
    }

    @Test
    fun `new admission distinguishes unavailable workflow harness limits and accepted input`() = Fixture().use { f ->
        error(f.send(body = f.body().replace("reconstruct", "validate")), 503, "CAPABILITY_UNAVAILABLE")
        error(f.send(body = f.body().replace(CAPABILITY, "unregistered_harness")), 503, "CAPABILITY_UNAVAILABLE")
        error(f.send(body = f.body().replace("\"16\"", "\"17\"")), 503, "CAPABILITY_UNAVAILABLE")
        error(f.send(body = f.body().replace("\"inputRevisionId\":null", "\"inputRevisionId\":\"unaccepted_revision\"")), 422, "INPUT_REVISION_UNAVAILABLE")
        val missing = f.send(target = f.path.replace(f.job.id, "f".repeat(32))); error(missing, 404, "NOT_FOUND")
        assertTrue(f.snapshot().attempts.isEmpty()); assertEquals(0, f.calls.get())
        run(f.send()); assertEquals(1, f.calls.get())
    }

    @Test
    fun `nullable harness and maximum unsigned decimal limits survive the wire without truncation`() = Fixture(
        capability = null, limits = WorkflowExecutionLimits(ULong.MAX_VALUE, ULong.MAX_VALUE, ULong.MAX_VALUE, ULong.MAX_VALUE),
    ).use { f ->
        val result = run(f.send())
        assertEquals(JsonNull, result["harnessCapabilityId"])
        val limits = result.getValue("limits").jsonObject
        assertTrue(limits.values.all { it.jsonPrimitive.isString && it.jsonPrimitive.content == ULong.MAX_VALUE.toString() })
        assertEquals(1, f.calls.get()); assertNull(f.snapshot().acceptedRevision)
    }

    @Test
    fun `restart with registrations removed keeps authenticated retained replay and refuses fresh work`() {
        val root = createTempDirectory("web-workflow-start-restart-")
        lateinit var jobId: String; lateinit var original: String; lateinit var runId: String
        try {
            Fixture(root = root, deferred = true, deleteRoot = false).use { f ->
                jobId = f.job.id; original = f.version(); runId = run(f.send(headers = f.headers(original))).getValue("runId").jsonPrimitive.content
                assertEquals(0, f.calls.get())
            }
            Fixture(root = root, reuseJob = jobId, registered = false, deleteRoot = false).use { f ->
                val before = f.state().readBytes()
                val replay = f.send(headers = f.headers(original))
                assertEquals(runId, run(replay).getValue("runId").jsonPrimitive.content)
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
                assertContentEquals(before, f.state().readBytes()); assertEquals(0, f.calls.get()); assertTrue(f.pending.isEmpty())
                error(f.send(headers = f.headers(key = "restart_fresh_start_key")), 503, "CAPABILITY_UNAVAILABLE")
                assertEquals(1, f.snapshot().attempts.size)
            }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `submission refusal retains a failed run and keyed replay never reschedules captured tasks`() {
        for (failure in listOf(RejectedExecutionException("PRIVATE_START_SCHEDULER"), IllegalStateException("PRIVATE_START_SCHEDULER"))) {
            Fixture(scheduleFailure = failure).use { f ->
                val original = f.version(); val response = f.send(headers = f.headers(original))
                if (failure is RejectedExecutionException) assertEquals("REFUSED", run(response).getValue("terminalReason").jsonPrimitive.content)
                else error(response, 503, "SCHEDULING_FAILED")
                val before = f.state().readBytes(); val attempt = f.snapshot().latestRun!!
                assertEquals(WorkflowRunState.FAILED, attempt.state); assertEquals(1, f.pending.size)
                val replay = f.send(headers = f.headers(original)); assertEquals(attempt.runId, run(replay).getValue("runId").jsonPrimitive.content)
                assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElseThrow())
                f.pending.remove().run(); assertEquals(0, f.calls.get()); assertContentEquals(before, f.state().readBytes())
            }
        }
    }

    @Test
    fun `publication failures cannot return success or leak private causes`() {
        for (point in listOf(WorkflowStoreFaultPoint.AFTER_TEMP_FSYNC, WorkflowStoreFaultPoint.AFTER_RENAME)) Fixture().use { f ->
            val headers = f.headers()
            f.fault = point
            val response = f.send(headers = headers)
            error(response, 503, if (point == WorkflowStoreFaultPoint.AFTER_RENAME) "RECOVERY_REQUIRED" else "PERSISTENCE_FAILED")
            assertTrue(response.headers().firstValue("Location").isEmpty); assertEquals(0, f.calls.get())
            if (point == WorkflowStoreFaultPoint.AFTER_RENAME) error(f.send(headers = headers), 503, "RECOVERY_REQUIRED")
        }
    }

    private fun run(response: HttpResponse<String>): JsonObject {
        assertEquals(202, response.statusCode(), response.body()); assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow())
        val document = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals("run", document.getValue("kind").jsonPrimitive.content)
        assertEquals(document.getValue("requestId").jsonPrimitive.content, response.headers().firstValue("X-Request-ID").orElseThrow())
        val run = document.getValue("data").jsonObject
        assertEquals("\"${run.getValue("version").jsonPrimitive.content}\"", response.headers().firstValue("ETag").orElseThrow())
        assertFalse(response.body().contains("PRIVATE_START_")); return run
    }
    private fun error(response: HttpResponse<String>, status: Int, code: String) {
        assertEquals(status, response.statusCode(), response.body())
        assertEquals(code, Json.parseToJsonElement(response.body()).jsonObject.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        assertFalse(response.body().contains("PRIVATE_START_"))
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
        const val KEY = "http_start_request_key_1234"
        val LIMITS = WorkflowExecutionLimits(60_000uL, 15_000uL, 1_048_576uL, 16uL)
    }
}
