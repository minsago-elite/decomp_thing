package decompengine.web

import decompengine.jobs.AgentProgressJournal
import decompengine.jobs.JobStore
import decompengine.jobs.NewWorkflowAttempt
import decompengine.jobs.WorkflowAttemptStore
import decompengine.jobs.WorkflowExecutionLimits
import decompengine.jobs.WorkflowJobInspection
import decompengine.jobs.WorkflowKind
import decompengine.jobs.WorkflowRunState
import decompengine.jobs.WorkflowTerminalReason
import decompengine.jobs.WorkflowTransition
import decompengine.jobs.elfFixture
import io.github.optimumcode.json.schema.JsonSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Response-code matrix driven by the documented route table in docs/web-api.md and the closed
 * contracts/web/v1 schema. Every documented method and route is probed through the real listener,
 * access policy and dispatcher; every JSON body must validate against the producer schema.
 *
 * To add a route: document it in the "HTTP route matrix" table, then add its live methods and
 * fixture outcome to [live]. A documented route without a [live] entry is reserved and must stay
 * an authenticated typed 404, so a route that goes live without an entry fails here by name.
 */
class WebRouteMatrixTest {
    private val root: Path = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp")), "web-route-matrix-")
    private val http: HttpClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()

    @AfterTest fun cleanup() { http.close(); root.toFile().deleteRecursively() }

    /** Fixture outcome for a session-authorized GET (status plus response kind or error code). */
    private data class Outcome(val status: Int, val kindOrCode: String)

    private enum class Query { NONE, PAGED, ROUTE_SPECIFIC }

    private data class Live(
        val methods: Set<String>,
        val get: Outcome? = null,
        val query: Query = Query.NONE,
        val media: String = JSON,
        /** Mutation media type checked before CSRF/session (multipart upload uses its own). */
        val mutationType: String = JSON,
        /** Authorized mutation refusal in this inert fixture; never admits a workflow. */
        val mutationRefusal: Outcome? = null,
    )

    /** Keys are documented templates after prefix and brace expansion, exactly as [documentedRoutes] yields them. */
    private val live: Map<String, Live> = mapOf(
        "/api/v1/session" to Live(setOf("POST", "DELETE")),
        "/api/v1/bootstrap" to Live(setOf("GET"), Outcome(200, "bootstrap")),
        "/api/v1/jobs" to Live(setOf("GET", "POST"), Outcome(200, "jobs"), Query.PAGED,
            mutationType = "multipart/form-data; boundary=route_matrix"),
        "/api/v1/recovery" to Live(setOf("GET", "HEAD"), Outcome(200, "recovery")),
        "/api/v1/uploads/{uploadId}" to Live(setOf("GET"), Outcome(404, "NOT_FOUND")),
        "/api/v1/agent/preflight" to Live(setOf("GET", "POST"), Outcome(200, "agentPreflight")),
        "$J" to Live(setOf("GET"), Outcome(200, "job")),
        "$J/runs" to Live(setOf("GET"), Outcome(200, "runs"), Query.PAGED),
        "$J/repositories" to Live(setOf("GET", "POST"), Outcome(200, "gitRepositories"),
            mutationRefusal = Outcome(428, "PRECONDITION_REQUIRED")),
        "$R" to Live(setOf("GET"), Outcome(200, "run")),
        "$R/progress-pin" to Live(setOf("GET", "PUT"), Outcome(200, "progressPin")),
        "$R/cancel" to Live(setOf("POST")),
        "$R/recover" to Live(setOf("POST"), mutationRefusal = Outcome(503, "CAPABILITY_UNAVAILABLE")),
        "$R/controls" to Live(setOf("GET"), Outcome(200, "attemptControls")),
        "$R/queue-position" to Live(setOf("GET"), Outcome(200, "queuePosition")),
        "$R/snapshot" to Live(setOf("GET"), Outcome(200, "snapshot")),
        "$R/events" to Live(setOf("GET"), Outcome(200, "events"), Query.PAGED),
        "$R/events?transport=poll" to Live(setOf("GET"), Outcome(200, "events"), Query.PAGED),
        "$R/reports/{reportId}" to Live(setOf("GET"), Outcome(200, "report")),
        "$R/source-catalog" to Live(setOf("GET"), Outcome(503, "SOURCE_CATALOG_UNAVAILABLE"), Query.PAGED),
        "$R/reports/revision-validation" to Live(setOf("GET", "HEAD"), Outcome(400, "VALIDATION_FAILED"), Query.ROUTE_SPECIFIC),
        "$R/validation-history" to Live(setOf("GET", "HEAD"), Outcome(200, "validationHistory"), Query.ROUTE_SPECIFIC),
        "$R/revisions/{revisionId}/sources" to Live(setOf("GET", "HEAD"), Outcome(404, "REVISION_NOT_FOUND"), Query.PAGED),
        "$R/revisions/{revisionId}/source-search" to Live(
            setOf("GET", "HEAD"), Outcome(422, "VALIDATION_FAILED"), Query.ROUTE_SPECIFIC),
        "$R/revisions/{revisionId}/source-directories/{directoryId}" to
            Live(setOf("GET", "HEAD"), Outcome(404, "REVISION_NOT_FOUND"), Query.PAGED),
        "$R/revisions/{revisionId}/source-files/{fileId}" to Live(setOf("GET", "HEAD"), Outcome(404, "SOURCE_FILE_NOT_FOUND")),
        "$R/revisions/{revisionId}/source-files/{fileId}/chunk" to
            Live(setOf("GET", "HEAD"), Outcome(404, "SOURCE_FILE_NOT_FOUND"), Query.ROUTE_SPECIFIC),
        "$R/revisions/{revisionId}/source-files/{fileId}/content" to
            Live(setOf("GET", "HEAD"), Outcome(404, "SOURCE_FILE_NOT_FOUND"), Query.ROUTE_SPECIFIC, media = OCTETS),
        "$J/artifacts/{artifactId}/content" to Live(setOf("GET", "HEAD"), Outcome(200, OCTETS), media = OCTETS),
    )

    /** Documented statuses that this matrix cannot produce without a fault injector, and where they are owned. */
    private val statusesOwnedElsewhere = mapOf(
        429 to "decompengine.web.WebAdmissionBoundsTest",
        500 to "decompengine.web.WebNegotiationMatrixTest",
        503 to "decompengine.web.UploadUncertaintyHttpTest",
    )
    /** Documented in the error table, emitted by no current producer path. */
    private val reservedStatuses = setOf(501, 504)

    private val schema = JsonSchema.fromDefinition(Files.readString(Path.of("contracts/web/v1/contract.schema.json")))
    private val observed = sortedSetOf<String>()

    @Test
    fun `every documented route and method answers its typed status and content contract`() = withServer { server, fixture ->
        val documented = documentedRoutes()
        assertTrue(documented.size >= 40, "the documented route table was not found or parsed: ${documented.size}")
        val stale = live.keys - documented.map { it.template }.toSet()
        assertTrue(stale.isEmpty(), "live matrix entries are not documented in docs/web-api.md: $stale")
        val before = storageDigest()
        val session = signIn(server)

        for (route in documented) {
            val spec = live[route.template]
            val path = fixture.resolve(route.template)
            val label = "${route.method} ${route.template}"
            val mutation = route.method in MUTATIONS
            val contentType = spec?.mutationType ?: JSON
            // Origin and forwarding checks precede method, session and route selection everywhere.
            expectError(call(server, route.method, path, mapOf("Origin" to "http://attacker.invalid", "Content-Type" to contentType)
                + session.cookie), 403, "ORIGIN_DENIED", "$label foreign Origin")
            expectError(call(server, route.method, path, mapOf("Sec-Fetch-Site" to "cross-site") + session.all(server, contentType)),
                403, "ORIGIN_DENIED", "$label cross-site fetch")
            expectError(call(server, route.method, path, mapOf("X-Forwarded-For" to "192.0.2.1") + session.all(server, contentType)),
                403, "FORWARDED_HEADERS_DENIED", "$label forwarding header")

            if (spec == null) {
                // Reserved: no route may answer before session authorization, and an authorized
                // request receives a typed missing route rather than SPA HTML or a success.
                expectError(call(server, route.method, path, origin(server, mutation, contentType)), 401, "SESSION_REQUIRED", "$label reserved without session")
                expectError(call(server, route.method, path, session.all(server, contentType)), 404, "NOT_FOUND",
                    "$label is reserved; if it is now live, add it to WebRouteMatrixTest.live")
                continue
            }
            val allow = spec.methods.sorted().joinToString(", ")
            if (route.method !in spec.methods) {
                // A documented method reserved on a live resource is refused before session lookup.
                val response = call(server, route.method, path, session.all(server, contentType))
                expectError(response, 405, "METHOD_NOT_ALLOWED", "$label reserved method")
                assertEquals(allow, response.header("Allow"), "$label Allow")
                continue
            }
            if (route.template != "/api/v1/session" || route.method != "POST") {
                expectError(call(server, route.method, path, origin(server, mutation, contentType)), 401, "SESSION_REQUIRED", "$label without session")
            }
            // Check method/Allow behavior for mutation-only resources as well as reads.
            for (other in listOf("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE") - spec.methods) {
                val response = call(server, other, path, session.all(server, contentType))
                expectError(response, 405, "METHOD_NOT_ALLOWED", "$label as $other")
                assertEquals(allow, response.header("Allow"), "$label as $other Allow")
            }
            if (mutation) {
                expectError(call(server, route.method, path, session.cookie + mapOf("Content-Type" to contentType)), 403, "ORIGIN_DENIED", "$label without Origin")
                expectError(call(server, route.method, path, session.all(server, "text/plain")), 415, "UNSUPPORTED_MEDIA_TYPE", "$label text body")
                if (route.template != "/api/v1/session") {
                    expectError(call(server, route.method, path, session.cookie + origin(server, true, contentType)), 403, "CSRF_DENIED", "$label without CSRF")
                }
                spec.mutationRefusal?.let { expected ->
                    expectError(call(server, route.method, path, session.all(server, contentType)),
                        expected.status, expected.kindOrCode, "$label without a registered workflow")
                }
                continue
            }
            if (route.method == "HEAD") continue
            val accept = if (spec.media == OCTETS) "application/octet-stream" else JSON
            val expected = checkNotNull(spec.get) { "$label needs a fixture outcome" }
            val read = call(server, "GET", path, session.cookie + mapOf("Accept" to accept))
            assertEquals(expected.status, read.statusCode(), "$label fixture status: ${read.text()}")
            if (expected.status < 400) {
                assertEquals(if (spec.media == OCTETS) OCTETS else "$JSON; charset=utf-8", read.header("Content-Type"), label)
                assertEquals("no-store", read.header("Cache-Control"), label)
                assertEquals("nosniff", read.header("X-Content-Type-Options"), label)
                assertTrue(read.header("X-Request-ID")?.matches(Regex("[0-9a-f-]{36}")) == true, label)
                if (spec.media == JSON) {
                    assertEnvelope(read, expected.kindOrCode, label)
                    // A stream or byte row names no JSON document; its JSON fallback is documented on its own row.
                    assertTrue(route.documents.isEmpty() || expected.kindOrCode in route.documents,
                        "$label returns ${expected.kindOrCode}, documented ${route.documents}")
                }
            } else expectError(read, expected.status, expected.kindOrCode, "$label fixture")
            if ("HEAD" in spec.methods) {
                val head = call(server, "HEAD", path, session.cookie + mapOf("Accept" to accept))
                assertEquals(read.statusCode(), head.statusCode(), "$label HEAD status")
                assertEquals(read.header("Content-Type"), head.header("Content-Type"), "$label HEAD type")
                assertTrue(head.body().isEmpty(), "$label HEAD body")
                observe(head)
            }
            val refused = if (spec.media == OCTETS) "application/json" else "text/html"
            expectError(call(server, "GET", path, session.cookie + mapOf("Accept" to refused)), 406, "NOT_ACCEPTABLE", "$label Accept $refused")
            val separator = if ('?' in path) "&" else "?"
            when (spec.query) {
                Query.NONE -> expectError(call(server, "GET", "$path${separator}unsupported=1", session.cookie),
                    400, "VALIDATION_FAILED", "$label unknown query")
                Query.PAGED -> for (limit in listOf("0", "201", "01", "x")) {
                    expectError(call(server, "GET", "$path${separator}limit=$limit", session.cookie), 422, "VALIDATION_FAILED", "$label limit=$limit")
                }
                Query.ROUTE_SPECIFIC -> Unit
            }
        }

        // The events route also negotiates its stream transport with the same session.
        val stream = http.send(HttpRequest.newBuilder(URI(server.base + fixture.resolve("$R/events")))
            .header("Accept", "text/event-stream").header("Cookie", session.cookie.getValue("Cookie"))
            .timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofInputStream())
        stream.body().close()
        assertEquals(200, stream.statusCode())
        assertEquals("text/event-stream; charset=utf-8", stream.headers().firstValue("Content-Type").orElse(null))
        assertEquals(before, storageDigest(), "matrix probes must not change stored job bytes")
    }

    @Test
    fun `every documented error status is produced through HTTP or owned by a named suite`() = withServer { server, fixture ->
        val session = signIn(server)
        val run = fixture.resolve(R)
        val runs = fixture.resolve("$J/runs")
        val first = call(server, "GET", "$runs?limit=1", session.cookie)
        assertEnvelope(first, "runs", "first attempt page")
        val cursor = checkNotNull(Json.parseToJsonElement(first.text()).jsonObject.getValue("data").jsonObject
            .getValue("page").jsonObject.getValue("nextCursor").jsonPrimitive.contentOrNull) { "two attempts need a continuation" }
        val cancel = "$run/cancel"
        val key = mapOf("Idempotency-Key" to "route-matrix-cancel-1")
        expectError(call(server, "POST", cancel, session.all(server) + key, "{\"action\":\"cancel\"}"), 428, "PRECONDITION_REQUIRED", "cancel without guard")
        expectError(call(server, "POST", cancel, session.all(server) + key + mapOf("If-Match" to "\"stale_version\""),
            "{\"action\":\"cancel\"}"), 412, "VERSION_CONFLICT", "stale cancel guard")
        expectError(call(server, "POST", cancel, session.all(server) + key + mapOf("If-Match" to "\"stale_version\""),
            "{\"action\":\"cancel\",\"pad\":\"${"x".repeat(2048)}\"}"), 413, "BODY_TOO_LARGE", "oversized cancel")
        val version = Json.parseToJsonElement(call(server, "GET", run, session.cookie).text()).jsonObject.getValue("data")
            .jsonObject.getValue("version").jsonPrimitive.content
        val etag = "\"$version\""
        val accepted = call(server, "POST", cancel, session.all(server) + key + mapOf("If-Match" to etag), "{\"action\":\"cancel\"}")
        // Startup reconciliation interrupted the abandoned queued attempt, so its recorded intent is a terminal 200.
        assertEnvelope(accepted, "run", "cancel reconciled attempt")
        assertEquals(200, accepted.statusCode())
        expectError(call(server, "GET", "$runs?limit=1&cursor=$cursor", session.cookie), 410, "CURSOR_EXPIRED", "changed attempt history")
        expectError(call(server, "GET", "$runs?limit=1&cursor=forged", session.cookie), 400, "INVALID_CURSOR", "forged cursor")
        val upload = mapOf("Idempotency-Key" to "route-matrix-upload-1")
        val created = call(server, "POST", "/w/api/v1/jobs", session.all(server, MULTIPART) + upload, body = multipart("first.elf"))
        assertEnvelope(created, "job", "keyed upload")
        assertEquals(201, created.statusCode())
        expectError(call(server, "POST", "/w/api/v1/jobs", session.all(server, MULTIPART) + upload, body = multipart("second.elf")),
            409, "IDEMPOTENCY_CONFLICT", "upload key reuse")
        expectError(call(server, "GET", "/w/api/v1/jobs?limit=0", session.cookie), 422, "VALIDATION_FAILED", "page limit")
        // The remaining transport statuses come from the shared negotiation and session probes.
        expectError(call(server, "GET", "/w/api/v1/jobs", session.cookie + mapOf("Accept" to "text/html")), 406, "NOT_ACCEPTABLE", "Accept")
        expectError(call(server, "PUT", "/w/api/v1/bootstrap", session.all(server)), 405, "METHOD_NOT_ALLOWED", "method")
        expectError(call(server, "POST", cancel, session.all(server, "text/plain")), 415, "UNSUPPORTED_MEDIA_TYPE", "media type")
        expectError(call(server, "GET", "/w/api/v1/jobs/${"f".repeat(32)}", session.cookie), 404, "NOT_FOUND", "missing job")
        expectError(call(server, "GET", "/w/api/v1/jobs"), 401, "SESSION_REQUIRED", "no session")
        expectError(call(server, "POST", cancel, session.cookie + origin(server, true)), 403, "CSRF_DENIED", "no CSRF")
        expectError(call(server, "GET", "/w/api/v1/jobs?unsupported=1", session.cookie), 422, "VALIDATION_FAILED", "unknown filter")
        expectError(call(server, "GET", "${fixture.resolve(J)}?unsupported=1", session.cookie), 400, "VALIDATION_FAILED", "unknown query")

        val documented = documentedErrorStatuses()
        assertTrue(documented.containsAll(listOf(400, 401, 403, 404, 405, 406, 409, 410, 412, 413, 415, 422, 428, 429, 500, 503)),
            "the documented error table was not found or parsed: $documented")
        val statuses = observed.map { it.substringBefore(' ').toInt() }.toSet()
        for (status in documented) {
            when {
                status in statuses -> Unit
                status in reservedStatuses -> Unit
                status in statusesOwnedElsewhere -> Class.forName(statusesOwnedElsewhere.getValue(status))
                else -> fail("documented status $status is neither produced by this matrix nor owned by a named suite; observed $observed")
            }
        }
        assertTrue((statuses intersect reservedStatuses).isEmpty(), "a reserved status is now produced; document and test it: $observed")
    }

    @Test
    fun `contract request fixtures and malformed bodies are refused before any state change`() = withServer { server, fixture ->
        val session = signIn(server)
        val run = fixture.resolve(R)
        val guard = mapOf("If-Match" to "\"stale_version\"", "Idempotency-Key" to "route-matrix-fixture-1")
        // Request kinds bound to live mutation routes, with the outcome a schema-valid body reaches.
        val routes = mapOf(
            "workflowCancelRequest" to Triple("POST", "$run/cancel", guard),
            "progressPinRequest" to Triple("PUT", "$run/progress-pin", guard),
            "agentPreflightRequest" to Triple("POST", "/w/api/v1/agent/preflight", emptyMap()),
            "sessionStartRequest" to Triple("POST", "/w/api/v1/session", emptyMap()),
        )
        val validOutcome = mapOf(
            "workflowCancelRequest" to (412 to "VERSION_CONFLICT"),
            "progressPinRequest" to (412 to "VERSION_CONFLICT"),
            "agentPreflightRequest" to (202 to "agentPreflight"),
            // The synthetic fixture token is schema-valid but deliberately not a server-issued token.
            "sessionStartRequest" to (400 to "VALIDATION_FAILED"),
        )
        val manifest = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1/fixtures.json"))).jsonObject
        var exercised = 0
        val before = storageDigest()
        for (entry in manifest.getValue("fixtures").let { it as kotlinx.serialization.json.JsonArray }) {
            val file = entry.jsonObject.getValue("file").jsonPrimitive.content
            val document = Json.parseToJsonElement(Files.readString(Path.of("contracts/web/v1").resolve(file))).jsonObject
            val kind = document.getValue("kind").jsonPrimitive.content
            val (method, path, headers) = routes[kind] ?: continue
            val valid = entry.jsonObject.getValue("valid").jsonPrimitive.content == "true"
            val credentials = if (kind == "sessionStartRequest") origin(server, true) else session.all(server)
            val response = call(server, method, path, credentials + headers, document.getValue("data").toString())
            if (valid) {
                val (status, kindOrCode) = validOutcome.getValue(kind)
                if (status < 400) { assertEquals(status, response.statusCode(), file); assertEnvelope(response, kindOrCode, file) }
                else expectError(response, status, kindOrCode, file)
            } else {
                assertTrue(response.statusCode() in setOf(400, 422), "$file must be refused as invalid: ${response.statusCode()} ${response.text()}")
                expectError(response, response.statusCode(), errorCode(response), file)
            }
            exercised++
        }
        assertTrue(exercised >= 7, "contract request fixtures were not exercised: $exercised")
        // Syntax failures are uniformly 400 MALFORMED_JSON; a well-formed body of the wrong shape is a validation refusal.
        val malformed = listOf("{", "{\"action\":\"cancel\",\"action\":\"cancel\"}", "", "{\"pinned\":false}x")
        val misshapen = listOf("[]", "null", "\"cancel\"", "{}")
        for ((method, path, headers) in routes.values.filter { it.second != "/w/api/v1/session" }) {
            for (body in malformed) {
                expectError(call(server, method, path, session.all(server) + headers, body), 400, "MALFORMED_JSON", "$method $path body '$body'")
            }
            for (body in misshapen) {
                val response = call(server, method, path, session.all(server) + headers, body)
                assertTrue(response.statusCode() in setOf(400, 422), "$method $path body '$body': ${response.text()}")
                expectError(response, response.statusCode(), "VALIDATION_FAILED", "$method $path body '$body'")
            }
            expectError(call(server, method, path, session.all(server) + headers, body = byteArrayOf(0x7b, 0x22, 0xff.toByte(), 0x22, 0x7d)),
                400, "MALFORMED_JSON", "$method $path invalid UTF-8")
            expectError(call(server, method, path, session.all(server) + headers, "{\"pad\":\"${"x".repeat(4096)}\"}"),
                413, "BODY_TOO_LARGE", "$method $path oversized body")
        }
        // Agent preflight leaves storage untouched; the inert inspector only fails its own snapshot.
        assertEquals(before, storageDigest(), "refused contract inputs must not change stored job bytes")
    }

    // ---- fixture, transport and contract helpers ----

    private class Fixture(private val jobId: String, private val runId: String, private val artifactId: String) {
        fun resolve(template: String): String = "/w" + template
            .replace("{jobId}", jobId).replace("{runId}", runId).replace("{artifactId}", artifactId)
            .replace("{uploadId}", "0".repeat(32)).replace("{reportId}", "exploration")
            .replace("{revisionId}", "revision_missing").replace("{fileId}", "file_missing")
            .replace("{directoryId}", "root").replace("{repositoryId}", "repository_missing")
            .replace("{worktreeId}", "worktree_missing").replace("{operationId}", "operation_missing")
    }

    private class Session(val cookie: Map<String, String>, private val csrf: String) {
        fun all(server: Server, contentType: String = JSON): Map<String, String> =
            cookie + mapOf("Origin" to server.base, "Content-Type" to contentType, "X-CSRF-Token" to csrf)
    }

    private class Server(val upload: UploadServer) {
        val base = "http://127.0.0.1:${upload.serverPort}"
    }

    /** [documents] are the success kinds the row names, e.g. `200 runs`, `200 run`. */
    private data class DocumentedRoute(val method: String, val template: String, val documents: Set<String>)

    private fun withServer(block: (Server, Fixture) -> Unit) {
        val job = JobStore(root).createFromUpload("inert.elf", elfFixture())
        val runs = WorkflowAttemptStore.open(root).use { owner ->
            List(2) {
                val current = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                val attempt = owner.create(job.id, current.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
                // One older terminal attempt gives the attempt collection a continuation page.
                if (it == 0) owner.transition(job.id, attempt.runId, attempt.version, WorkflowTransition.Finish(
                    WorkflowRunState.CANCELLED, WorkflowTerminalReason.CANCELLED))
                attempt.runId
            }
        }
        val runId = runs.last()
        val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/$runId"))
        AgentProgressJournal(reports, "reconstruct").use { it.phase(decompengine.agent.AgentWorkflowPhase.PLANNING) }
        Files.writeString(reports.resolve("exploration.json"), "{\"fixture\":\"inert route matrix\"}")
        val upload = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("analysis must remain inert") },
            JobReconstructor { _, _ -> error("reconstruction must remain inert") }, uiMode = WebUiMode.SPA, basePath = "/w/",
            sensitiveValues = emptyList(), authenticationInspector = { error("inert fixture: no agent is launched") })
        upload.start()
        try {
            val server = Server(upload)
            val session = signIn(server)
            val report = call(server, "GET", "/w/api/v1/jobs/${job.id}/runs/$runId/reports/exploration", session.cookie)
            val href = Json.parseToJsonElement(report.text()).jsonObject.getValue("data").jsonObject
                .getValue("sourceArtifact").jsonObject.getValue("contentHref").jsonPrimitive.content
            val artifactId = href.substringAfter("/artifacts/").substringBefore('/')
            block(server, Fixture(job.id, runId, artifactId))
        } finally { upload.stop() }
    }

    private fun signIn(server: Server): Session {
        val response = call(server, "POST", "/w/api/v1/session", origin(server, true),
            "{\"token\":\"${server.upload.issueBrowserBootstrap().token}\"}")
        assertEnvelope(response, "session", "sign in")
        val csrf = Json.parseToJsonElement(response.text()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        return Session(mapOf("Cookie" to response.header("Set-Cookie")!!.substringBefore(';')), csrf)
    }

    private fun origin(server: Server, mutation: Boolean, contentType: String = JSON): Map<String, String> =
        if (mutation) mapOf("Origin" to server.base, "Content-Type" to contentType) else emptyMap()

    private fun call(server: Server, method: String, path: String, headers: Map<String, String> = emptyMap(),
                     text: String? = null, body: ByteArray? = null): HttpResponse<ByteArray> {
        val publisher = body?.let(HttpRequest.BodyPublishers::ofByteArray) ?: text?.let(HttpRequest.BodyPublishers::ofString)
            ?: HttpRequest.BodyPublishers.noBody()
        val builder = HttpRequest.newBuilder(URI(server.base + path)).timeout(Duration.ofSeconds(30)).method(method, publisher)
        if ("Accept" !in headers) builder.header("Accept", JSON)
        headers.forEach { (name, value) -> builder.header(name, value) }
        return http.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray()).also(::assertNoWebCors).also(::observe)
    }

    private fun observe(response: HttpResponse<ByteArray>) {
        if (response.statusCode() < 400) return
        val code = if (response.body().isEmpty()) "-" else errorCode(response)
        observed += "${response.statusCode()} $code"
    }

    private fun multipart(filename: String): ByteArray =
        "--route_matrix\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n\r\n".toByteArray() +
            elfFixture() + "\r\n--route_matrix--\r\n".toByteArray()

    private fun expectError(response: HttpResponse<ByteArray>, status: Int, code: String, label: String) {
        assertEquals(status, response.statusCode(), "$label: ${response.text()}")
        assertEquals("$JSON; charset=utf-8", response.header("Content-Type"), label)
        assertEquals("no-store", response.header("Cache-Control"), label)
        assertEquals("nosniff", response.header("X-Content-Type-Options"), label)
        if (response.request().method() == "HEAD") {
            assertTrue(response.body().isEmpty(), "$label HEAD body")
            return
        }
        assertEnvelope(response, "error", label)
        assertEquals(code, errorCode(response), label)
    }

    private fun assertEnvelope(response: HttpResponse<ByteArray>, kind: String, label: String) {
        val text = response.text()
        assertTrue(!text.trimStart().startsWith("<"), "$label received HTML")
        val body = Json.parseToJsonElement(text).jsonObject
        assertEquals(kind, body["kind"]?.jsonPrimitive?.content, "$label kind: $text")
        assertEquals(response.header("X-Request-ID"), body.getValue("requestId").jsonPrimitive.content, "$label request ID")
        val errors = mutableListOf<String>()
        if (!schema.validate(body) { errors += "${it.objectPath}: ${it.message}" }) {
            fail("$label violates contracts/web/v1/contract.schema.json: ${errors.take(8)} in ${text.take(512)}")
        }
    }

    private fun errorCode(response: HttpResponse<ByteArray>): String =
        (Json.parseToJsonElement(response.text()) as JsonObject).getValue("error").jsonObject.getValue("code").jsonPrimitive.content

    private fun HttpResponse<ByteArray>.header(name: String): String? = headers().firstValue(name).orElse(null)
    private fun HttpResponse<ByteArray>.text(): String = body().decodeToString()

    private fun storageDigest(): Map<String, String> = Files.walk(root).use { paths ->
        paths.filter(Files::isRegularFile).toList().associate { file ->
            root.relativize(file).toString() to MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file))
                .joinToString("") { "%02x".format(it) }
        }
    }

    companion object {
        private const val JSON = "application/json"
        private const val OCTETS = "application/octet-stream"
        private const val MULTIPART = "multipart/form-data; boundary=route_matrix"
        private val MUTATIONS = setOf("POST", "PUT", "PATCH", "DELETE")
        private const val J = "/api/v1/jobs/{jobId}"
        private const val R = "$J/runs/{runId}"
        private val docs: List<String> by lazy { Files.readAllLines(Path.of("docs/web-api.md")) }

        private fun table(heading: String, firstColumn: String): List<List<String>> {
            val start = docs.indexOfFirst { it.trim() == heading }
            check(start >= 0) { "docs/web-api.md lacks $heading" }
            val header = (start until docs.size).first { docs[it].startsWith("| $firstColumn") }
            return docs.drop(header + 2).takeWhile { it.startsWith("|") }
                .map { row -> row.trim().removePrefix("|").removeSuffix("|").split(" | ").map(String::trim) }
        }

        /** Expands `J`/`R`/`V`/`G` prefixes, shared methods (`GET`, `HEAD x`) and `{a,b}` alternatives. */
        private fun documentedRoutes(): List<DocumentedRoute> {
            val prefixes = mapOf("J" to J, "R" to R, "V" to "$J/revisions/{revisionId}", "G" to "$J/repositories/{repositoryId}")
            fun alternatives(path: String): List<String> {
                val match = Regex("\\{([^}]*,[^}]*)}").find(path) ?: return listOf(path)
                return match.groupValues[1].split(',').flatMap { alternatives(path.replaceRange(match.range, it.trim())) }
            }
            return table("## HTTP route matrix", "Method and route").flatMap { cells ->
                val pending = mutableListOf<String>()
                val documents = Regex("`[0-9]{3} ([A-Za-z]+)`").findAll(cells[1]).map { it.groupValues[1] }.toSet()
                Regex("`([^`]+)`").findAll(cells[0]).map { it.groupValues[1].trim() }.flatMap { token ->
                    val words = token.split(' ')
                    if (words.size == 1 && words[0].matches(Regex("[A-Z]+"))) { pending += words[0]; emptySequence() }
                    else {
                        check(words.size == 2 && words[0].matches(Regex("[A-Z]+"))) { "unparsed route matrix cell: ${cells[0]}" }
                        val raw = words[1]
                        val head = raw.substringBefore('/')
                        val path = prefixes[head]?.let { it + raw.removePrefix(head) } ?: raw
                        check(path.startsWith("/api/v1/")) { "route matrix entry is not under /api/v1/: ${cells[0]}" }
                        val methods = pending + words[0]
                        pending.clear()
                        methods.flatMap { method -> alternatives(path).map { DocumentedRoute(method, it, documents) } }.asSequence()
                    }
                }.toList()
            }.distinct()
        }

        private fun documentedErrorStatuses(): Set<Int> = table("## Errors, deadlines and concurrent mutations", "Status")
            .flatMap { cells -> Regex("`([0-9]{3})`").findAll(cells[0]).map { it.groupValues[1].toInt() }.toList() }.toSet()
    }
}
