package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Canary tests for the shared redaction policy, sensitive-action audit and scoped support export,
 * driven through the production listener on successful and failing paths.
 */
class WebSensitiveBoundaryTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val canary = "CANARYsecret0123456789abcdefXYZ"

    private class Session(val cookie: String, val csrf: String)

    @Test fun `injected canaries and private paths stay out of assets, bootstrap, DTOs, errors, logs, audit and exports`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath())
        val root = Files.createTempDirectory(parent, "store-$canary-")
        val diagnostics = CopyOnWriteArrayList<String>()
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, uiMode = WebUiMode.SPA, basePath = "/workbench/",
            sensitiveValues = listOf(canary), redactionEnvironment = mapOf("DECOMP_TEST_API_TOKEN" to canary),
            requestDiagnosticOutput = { diagnostics += it })
        val observed = mutableListOf<String>()
        fun record(response: HttpResponse<String>): HttpResponse<String> = response.also {
            observed += it.body(); observed += it.headers().map().toString()
        }
        try {
            server.start()
            // Served assets: the document and every same-origin asset it references.
            val index = record(get(server, "/workbench/", accept = "text/html"))
            assertEquals(200, index.statusCode())
            val assets = Regex("(?:src|href)=\"(/workbench/assets/[^\"]+)\"").findAll(index.body()).map { it.groupValues[1] }.toSet()
            assertTrue(assets.isNotEmpty())
            assets.forEach { assertEquals(200, record(get(server, it, accept = "*/*")).statusCode(), it) }

            val session = establish(server)
            val bootstrap = record(get(server, "/workbench/api/v1/bootstrap", session))
            assertEquals(200, bootstrap.statusCode())

            // A failing mutation (missing CSRF), an accepted upload and its idempotent replay.
            val denied = record(upload(server, session, csrf = false, filename = "denied.elf"))
            assertEquals(403, denied.statusCode())
            val uploaded = record(upload(server, session, filename = "upload-$canary.elf"))
            assertEquals(201, uploaded.statusCode())
            val job = Json.parseToJsonElement(uploaded.body()).jsonObject.getValue("data").jsonObject
            val jobId = job.getValue("jobId").jsonPrimitive.content
            assertEquals("upload-[redacted].elf", job.getValue("displayFilename").jsonPrimitive.content)
            val replay = record(upload(server, session, filename = "upload-$canary.elf"))
            assertEquals("true", replay.headers().firstValue("Idempotency-Replayed").orElse(null))
            record(get(server, "/workbench/api/v1/jobs", session))
            record(get(server, "/workbench/api/v1/jobs/$jobId", session))
            assertEquals(404, record(get(server, "/workbench/api/v1/jobs/${"f".repeat(32)}", session)).statusCode())
            assertEquals(401, record(get(server, "/workbench/api/v1/jobs")).statusCode())
            val cancel = record(request(server, "/workbench/api/v1/jobs/$jobId/runs/run_missing/cancel", session, "POST",
                "{\"action\":\"cancel\"}", mapOf("If-Match" to "\"version_1\"", "Idempotency-Key" to "cancel_key_0123456789")))
            assertEquals(404, cancel.statusCode())

            // Explicit scope only: no default, no unknown parameters, no unknown job.
            assertEquals(400, record(get(server, "/workbench/api/v1/support-export", session)).statusCode())
            assertEquals(400, record(get(server, "/workbench/api/v1/support-export?scope=server&path=/etc", session)).statusCode())
            assertEquals(400, record(get(server, "/workbench/api/v1/support-export?scope=job&jobId=../x", session)).statusCode())
            assertEquals(404, record(get(server, "/workbench/api/v1/support-export?scope=job&jobId=${"e".repeat(32)}", session)).statusCode())
            val serverExport = exportData(record(get(server, "/workbench/api/v1/support-export?scope=server", session)))
            assertEquals("web-redaction-v1", serverExport.getValue("redactionVersion").jsonPrimitive.content)
            assertEquals(listOf("runtime", "limits", "capabilities", "recovery", "audit"), sections(serverExport).keys.toList())
            val omitted = serverExport.getValue("omittedSections").jsonArray.associate {
                it.jsonObject.getValue("id").jsonPrimitive.content to it.jsonObject.getValue("reason").jsonPrimitive.content
            }
            assertEquals("not-in-scope", omitted["job"])
            assertEquals("secret", omitted["credentials"])
            assertEquals("private-configuration", omitted["environment"])
            assertEquals("job-content", omitted["input-binary"])

            // An entry is written as its handler exits, after the response; wait for the job's three actions.
            awaitAudit(server, 3, jobId)
            val jobExport = exportData(record(get(server, "/workbench/api/v1/support-export?scope=job&jobId=$jobId", session)))
            assertEquals(jobId, jobExport.getValue("scope").jsonObject.getValue("jobId").jsonPrimitive.content)
            val jobSections = sections(jobExport)
            assertEquals(listOf("job", "runs", "audit"), jobSections.keys.toList())
            val entries = jobSections.getValue("audit").getValue("entries").jsonArray.map { it.jsonObject }
            // Entries are sequenced as each handler exits, which need not match the order responses arrived.
            assertEquals(listOf("job.upload:accepted:201", "job.upload:replayed:201", "run.cancel:rejected:404"), entries.map {
                "${it.getValue("action").jsonPrimitive.content}:${it.getValue("outcome").jsonPrimitive.content}:${it.getValue("status")}"
            }.sorted())
            assertTrue(entries.all { it.getValue("target").jsonObject.getValue("jobId").jsonPrimitive.content == jobId })

            // Server-wide audit includes refused requests, attributed by digest only.
            awaitAudit(server, 11)
            val exported = sections(exportData(record(get(server, "/workbench/api/v1/support-export?scope=server", session))))
                .getValue("audit").getValue("entries").jsonArray.map { it.jsonObject }
            awaitAudit(server, 12)
            val audit = server.audit.read().entries.map { it.toJson() }
            assertEquals(audit.take(11), exported, "the export carries the durable entries")
            val summary = audit.map {
                listOf("action", "outcome", "reasonCode").joinToString(":") { key -> it.getValue(key).toString().trim('"') }
            }
            assertEquals(listOf("session.start:accepted:null", "job.upload:rejected:CSRF_DENIED", "job.upload:accepted:null",
                "job.upload:replayed:null", "run.cancel:rejected:NOT_FOUND", "support.export:rejected:VALIDATION_FAILED",
                "support.export:rejected:VALIDATION_FAILED", "support.export:rejected:VALIDATION_FAILED",
                "support.export:rejected:NOT_FOUND", "support.export:accepted:null", "support.export:accepted:null",
                "support.export:accepted:null").sorted(), summary.sorted())
            val digests = audit.map { it.getValue("actor").jsonObject.getValue("sessionDigest").jsonPrimitive.content }.toSet()
            assertEquals(1, digests.size, "one browser session performed every audited action")
            val exportTargets = audit.filter { it.getValue("action").jsonPrimitive.content == "support.export" }
                .map { (it.getValue("target").jsonObject.getValue("jobId") as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull }
            assertTrue(jobId in exportTargets, "a job-scoped export is attributed to its job")
            assertTrue("e".repeat(32) in exportTargets, "a refused export of a validated job ID keeps that target")
            assertEquals(1, server.audit.read(jobId).entries.count { it.action == WebAuditAction.SUPPORT_EXPORT })
            val cancelEntry = audit.single { it.getValue("action").jsonPrimitive.content == "run.cancel" }
            assertEquals(WebAuditRecorder.versionCommitment("version_1"),
                cancelEntry.getValue("target").jsonObject.getValue("expectedVersion").jsonPrimitive.content)
            assertEquals(WebAuditRecorder.runCommitment("run_missing"),
                cancelEntry.getValue("target").jsonObject.getValue("runId").jsonPrimitive.content)

            val auditBytes = Files.readString(root.resolve(".web-audit/current.jsonl"))
            val token = session.cookie.substringAfter('=')
            listOf(canary, token, session.csrf, "upload-", root.toString()).forEach {
                assertFalse(auditBytes.contains(it), "audit storage must not contain $it")
            }
            assertNotEquals(token, digests.single())
        } finally {
            server.stop()
            root.toFile().deleteRecursively()
        }
        val combined = observed.joinToString("\n") + diagnostics.joinToString("\n")
        assertFalse(combined.contains(canary), "a canary escaped into a served representation or log")
        assertFalse(combined.contains(root.toString()), "the private storage path escaped")
        assertFalse(combined.contains(parent.toString()), "a private host path escaped")
        assertTrue(diagnostics.isNotEmpty() && diagnostics.all { it.startsWith("web-http-failure request_id=") })
    }

    @Test fun `near-limit filenames stay readable in upload read listing and scoped export responses`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "bounded-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, uiMode = WebUiMode.SPA, basePath = "/workbench/",
            sensitiveValues = listOf("shortish9"), redactionEnvironment = mapOf("TEST_TOKEN" to "shortish9"))
        try {
            server.start()
            val session = establish(server)
            val uploaded = upload(server, session, filename = "shortish9".repeat(28) + ".c")
            assertEquals(201, uploaded.statusCode(), uploaded.body())
            fun data(response: HttpResponse<String>): JsonObject = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject
            val job = data(uploaded)
            val id = job.getValue("jobId").jsonPrimitive.content
            fun bounded(value: JsonObject) {
                assertEquals("[redacted]", value.getValue("displayFilename").jsonPrimitive.content)
                assertTrue(value.getValue("displayFilename").jsonPrimitive.content.length in 1..255)
            }
            bounded(job)
            val read = get(server, "/workbench/api/v1/jobs/$id", session)
            assertEquals(200, read.statusCode()); bounded(data(read))
            val listed = get(server, "/workbench/api/v1/jobs", session)
            assertEquals(200, listed.statusCode())
            bounded(data(listed).getValue("items").jsonArray.single().jsonObject)
            val exported = exportData(get(server, "/workbench/api/v1/support-export?scope=job&jobId=$id", session))
            bounded(sections(exported).getValue("job"))
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `server support export counts entries omitted by its audit window`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "window-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, uiMode = WebUiMode.SPA, basePath = "/workbench/")
        try {
            server.start()
            val session = establish(server)
            awaitAudit(server, 1)
            repeat(110) {
                server.audit.record(WebAuditActor.OPERATOR, WebAuditAction.RUN_CANCEL, WebAuditTarget(),
                    WebAuditOutcome.ACCEPTED, 202, null, null)
            }
            awaitAudit(server, 111)
            val page = sections(exportData(get(server, "/workbench/api/v1/support-export?scope=server", session))).getValue("audit")
            val entries = page.getValue("entries").jsonArray
            assertEquals(100, entries.size)
            assertEquals("12", entries.first().jsonObject.getValue("sequence").jsonPrimitive.content)
            assertEquals("111", entries.last().jsonObject.getValue("sequence").jsonPrimitive.content)
            assertEquals("11", page.getValue("omittedEntries").jsonPrimitive.content)
            assertEquals("false", page.getValue("complete").toString())
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `requested versions cannot persist configured cookie or csrf credentials even on denials`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "preconditions-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, uiMode = WebUiMode.SPA, basePath = "/workbench/",
            sensitiveValues = listOf(canary), redactionEnvironment = mapOf("TEST_TOKEN" to canary))
        try {
            server.start()
            val session = establish(server)
            val values = listOf(canary, session.cookie.substringAfter('='), session.csrf)
            for (authenticated in listOf(false, true)) for (value in values) {
                val denied = request(server, "/workbench/api/v1/jobs/${"a".repeat(32)}/runs/$value/cancel",
                    if (authenticated) session else null, "POST", "{}", mapOf("If-Match" to "\"$value\""))
                assertTrue(denied.statusCode() >= 400)
            }
            awaitAudit(server, 7)
            val stored = Files.readString(root.resolve(".web-audit/current.jsonl"))
            val exported = get(server, "/workbench/api/v1/support-export?scope=server", session)
            assertEquals(200, exported.statusCode())
            values.forEach { value ->
                assertFalse(stored.contains(value), "raw requested versions must not reach durable storage")
                assertFalse(exported.body().contains(value), "raw requested versions must not reach exports")
            }
            val entries = server.audit.read().entries.filter { it.action == WebAuditAction.RUN_CANCEL }
            assertEquals(6, entries.size)
            assertEquals(values.map { WebAuditRecorder.versionCommitment(it) }.toSet(), entries.map { it.target.expectedVersion }.toSet())
            assertEquals(values.map { WebAuditRecorder.runCommitment(it) }.toSet(), entries.map { it.target.runId }.toSet())
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `legacy JSON uploads are attributed to their job and legacy report downloads are redacted`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "legacy-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, sensitiveValues = listOf(canary),
            redactionEnvironment = mapOf("DECOMP_TEST_API_TOKEN" to canary))
        try {
            server.start()
            val origin = "http://127.0.0.1:${server.serverPort}"
            val headers = legacySessionHeaders(server)
            val boundary = "legacy_boundary"
            val payload = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"l.elf\"\r\n\r\n".toByteArray() +
                elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
            val uploaded = client.send(HttpRequest.newBuilder(URI("$origin/jobs")).header("Origin", origin)
                .header("Accept", "application/json").header("Content-Type", "multipart/form-data; boundary=$boundary")
                .apply { headers.forEach { (k, v) -> header(k, v) } }
                .POST(HttpRequest.BodyPublishers.ofByteArray(payload)).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(201, uploaded.statusCode(), uploaded.body())
            val jobId = Json.parseToJsonElement(uploaded.body()).jsonObject.getValue("id").jsonPrimitive.content
            assertEquals("/jobs/$jobId", uploaded.headers().firstValue("Location").orElse(null))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (server.audit.read(jobId).entries.none { it.action == WebAuditAction.JOB_UPLOAD } && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals(WebAuditOutcome.ACCEPTED, server.audit.read(jobId).entries.single { it.action == WebAuditAction.JOB_UPLOAD }.outcome)

            val reports = Files.createDirectories(root.resolve(jobId).resolve("reports"))
            Files.writeString(reports.resolve("exploration.json"), "{\"note\": \"token $canary at /home/someone/x\"}")
            Files.createDirectories(reports.resolve("source-tree/src"))
            Files.writeString(reports.resolve("source-tree/src/main.c"), "/* built in /home/someone/x */\n")
            fun download(path: String) = client.send(HttpRequest.newBuilder(URI("$origin/jobs/$jobId/artifacts/$path"))
                .apply { headers.forEach { (k, v) -> header(k, v) } }.GET().build(), HttpResponse.BodyHandlers.ofString())
            val report = download("reports/exploration.json")
            assertEquals(200, report.statusCode())
            assertFalse(report.body().contains(canary) || report.body().contains("/home/someone"), report.body())
            assertEquals("token [redacted] at [private-path]", Json.parseToJsonElement(report.body()).jsonObject.getValue("note").jsonPrimitive.content)
            assertEquals("/* built in /home/someone/x */\n", download("reports/source-tree/src/main.c").body(), "committed source is job content")
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `legacy operator inspection refusals and cancellations are audited with their public reason`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "operator-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") })
        try {
            server.start()
            val origin = "http://127.0.0.1:${server.serverPort}"
            val headers = legacySessionHeaders(server)
            for (path in listOf("/api/operator/auth-methods", "/api/operator/auth-methods/cancel")) {
                val response = client.send(HttpRequest.newBuilder(URI("$origin$path")).header("Origin", origin)
                    .header("Content-Type", "application/json").header("Accept", "application/json")
                    .apply { headers.forEach { (k, v) -> header(k, v) } }
                    .POST(HttpRequest.BodyPublishers.ofString("{}")).build(), HttpResponse.BodyHandlers.ofString())
                assertEquals(400, response.statusCode(), path)
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            fun operator() = server.audit.read().entries.filter { it.action.wireName.startsWith("operator.") }
            while (operator().size < 2 && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals(setOf("operator.auth-inspection", "operator.auth-inspection-cancel"), operator().map { it.action.wireName }.toSet())
            assertTrue(operator().all { it.outcome == WebAuditOutcome.REJECTED && it.reasonCode == "OPERATOR_INSPECTION_REJECTED" })
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `a base path that looks like a host directory survives bootstrap redaction`() {
        val root = Files.createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/web-sensitive").toAbsolutePath()), "base-")
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected") },
            JobReconstructor { _, _ -> error("unexpected") }, uiMode = WebUiMode.SPA, basePath = "/home/")
        try {
            server.start()
            val origin = "http://127.0.0.1:${server.serverPort}"
            val token = server.issueBrowserBootstrap().token
            val login = client.send(HttpRequest.newBuilder(URI("$origin/home/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, login.statusCode(), login.body())
            val cookie = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val bootstrap = client.send(HttpRequest.newBuilder(URI("$origin/home/api/v1/bootstrap")).header("Cookie", cookie)
                .header("Accept", "application/json").build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, bootstrap.statusCode())
            assertEquals("/home/", Json.parseToJsonElement(bootstrap.body()).jsonObject.getValue("data").jsonObject
                .getValue("basePath").jsonPrimitive.content)
        } finally { server.stop(); root.toFile().deleteRecursively() }
    }

    @Test fun `live and replayed event representations apply the same listener policy`() {
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val origin = "http://127.0.0.1:${http.address.port}"
        val access = LocalWebAccess(LocalWebAccessConfiguration(origin))
        val resources = WebStreamResources(maximumConnections = 2, lifetimeMs = 5000)
        val pages = WebProgressPages()
        val journal = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 1)
            put("queueDropped", 0); put("historyDropped", 0); put("truncated", false)
            put("events", buildJsonArray { add(buildJsonObject {
                put("sequence", 0); put("runId", "writer_$canary"); put("workflow", "reconstruct")
                put("time", "2026-09-06T00:00:00Z"); put("kind", "message"); put("text", "PRIVATE $canary /home/x")
            }) })
        }.toString().toByteArray()
        val stream = WebEventStream(access, resources, pages, { _, _ -> journal }, pollMs = 20, heartbeatMs = 40)
        val sessions = WebSessionController(access)
        val worker = Executors.newFixedThreadPool(2)
        http.executor = worker
        val context = http.createContext("/") { exchange ->
            try {
                when (exchange.requestURI.path) {
                    "/session" -> sessions.handle(exchange)
                    "/poll" -> {
                        val owner = checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead()))
                        sendWebApiResponse(exchange, 200, "events", pages.page(owner.sessionId, "job", "run", journal, exchange.requestURI.rawQuery))
                    }
                    else -> stream.open(exchange, checkNotNull(access.authorize(exchange, WebEndpointPolicy.privateRead())),
                        "job", "run", "/api/v1/jobs/job/runs/run/snapshot")
                }
            } catch (failure: WebAccessDenied) { access.sendDenied(exchange, failure) }
        }
        WebRedactionPolicy.install(context, WebRedactionPolicy.create(mapOf("DECOMP_TEST_TOKEN" to canary), emptyList(), emptyList()))
        http.start()
        try {
            val token = access.issueBootstrap().token
            val login = client.send(HttpRequest.newBuilder(URI("$origin/session")).header("Origin", origin)
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"$token\"}")).build(),
                HttpResponse.BodyHandlers.ofString())
            val cookie = login.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';')
            val live = client.send(HttpRequest.newBuilder(URI("$origin/events")).timeout(Duration.ofSeconds(3))
                .header("Cookie", cookie).header("Accept", "text/event-stream").build(), HttpResponse.BodyHandlers.ofInputStream())
            val data = live.body().bufferedReader().use { reader ->
                generateSequence { reader.readLine() }.first { it.startsWith("data: ") }.removePrefix("data: ")
            }
            val replay = client.send(HttpRequest.newBuilder(URI("$origin/poll?transport=poll")).header("Cookie", cookie).build(),
                HttpResponse.BodyHandlers.ofString()).body()
            val replayed = Json.parseToJsonElement(replay).jsonObject.getValue("data").jsonObject.getValue("items").jsonArray.single()
            assertEquals(Json.parseToJsonElement(data), replayed)
            assertEquals("[redacted]", replayed.jsonObject.getValue("payload").jsonObject.getValue("writerId").jsonPrimitive.content)
            listOf(data, replay).forEach {
                assertFalse(it.contains(canary)); assertFalse(it.contains("PRIVATE")); assertFalse(it.contains("/home/x"))
            }
        } finally {
            resources.shutdown(); http.stop(0); access.close(); worker.shutdownNow()
            worker.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    private fun awaitAudit(server: UploadServer, count: Int, jobId: String? = null) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (server.audit.read(jobId).entries.size < count && System.nanoTime() < deadline) Thread.sleep(10)
        assertEquals(count, server.audit.read(jobId).entries.size)
    }

    private fun exportData(response: HttpResponse<String>): JsonObject {
        assertEquals(200, response.statusCode(), response.body())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals("supportExport", body.getValue("kind").jsonPrimitive.content)
        return body.getValue("data").jsonObject
    }

    private fun sections(export: JsonObject): Map<String, JsonObject> = export.getValue("sections").jsonArray.associate {
        val section = it.jsonObject
        section.getValue("id").jsonPrimitive.content to (section.getValue("content") as? JsonObject ?: JsonObject(emptyMap()))
    }

    private fun establish(server: UploadServer): Session {
        val token = server.issueBrowserBootstrap().token
        val response = request(server, "/workbench/api/v1/session", null, "POST", "{\"token\":\"$token\"}")
        assertEquals(200, response.statusCode())
        val csrf = Json.parseToJsonElement(response.body()).jsonObject.getValue("data").jsonObject.getValue("csrfToken").jsonPrimitive.content
        return Session(response.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'), csrf)
    }

    private fun get(server: UploadServer, path: String, session: Session? = null, accept: String = "application/json") =
        request(server, path, session, "GET", null, mapOf("Accept" to accept))

    private fun request(server: UploadServer, path: String, session: Session?, method: String, body: String?,
                        headers: Map<String, String> = emptyMap()): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val all = mutableMapOf("Accept" to "application/json")
        if (method != "GET") all += mapOf("Origin" to origin, "Content-Type" to "application/json")
        if (session != null) {
            all["Cookie"] = session.cookie
            if (method != "GET") all["X-CSRF-Token"] = session.csrf
        }
        all += headers
        val builder = HttpRequest.newBuilder(URI(origin + path)).method(method,
            body?.let(HttpRequest.BodyPublishers::ofString) ?: HttpRequest.BodyPublishers.noBody())
        all.forEach { (key, value) -> builder.header(key, value) }
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }

    private fun upload(server: UploadServer, session: Session, csrf: Boolean = true, filename: String): HttpResponse<String> {
        val origin = "http://127.0.0.1:${server.serverPort}"
        val boundary = "sensitive_boundary"
        val payload = "--$boundary\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n\r\n".toByteArray() +
            elfFixture() + "\r\n--$boundary--\r\n".toByteArray()
        val builder = HttpRequest.newBuilder(URI("$origin/workbench/api/v1/jobs"))
            .POST(HttpRequest.BodyPublishers.ofByteArray(payload))
            .header("Accept", "application/json").header("Origin", origin).header("Cookie", session.cookie)
            .header("Content-Type", "multipart/form-data; boundary=$boundary").header("Idempotency-Key", "upload_key_0123456789")
        if (csrf) builder.header("X-CSRF-Token", session.csrf)
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString())
    }
}
