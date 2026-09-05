package decompengine.web

import decompengine.jobs.elfFixture
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileDeclaration
import decompengine.project.ProjectFileRole
import decompengine.project.ProjectLayoutProfile
import decompengine.project.ReconstructionProfile
import decompengine.project.SourceTreeManifest
import decompengine.project.SourceTreeGenerator
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredFunction
import decompengine.project.MakeProjectBuilder
import decompengine.project.ArchivalPackager
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.HttpURLConnection
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.Executor
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class UploadServerTest {
    @Test
    fun `HTML exploration uses supplied data and bounded unavailable report reads`() = withServer { server, root ->
        val id = uploadedJobId(server)
        val job = decompengine.jobs.JobStore(root).get(id)
        val reports = root.resolve(id).resolve("reports").createDirectories()
        val report = reports.resolve("exploration.json")
        val source = """{"confidence":{"score":0.63},"candidateCount":1,"expandedOutputSignatures":1,"newOutputSignatures":[],"candidates":[{"id":"supplied_case","source":"SEED","args":[],"stdinHex":""}],"observations":[]}"""
        report.writeText(source.replace("supplied_case", "stored_case"))
        val bytes = report.readBytes()
        val rendered = renderJob(job, explorationReport = Json.parseToJsonElement(source).jsonObject)
        assertTrue(rendered.contains("supplied_case"))
        assertTrue(!rendered.contains("stored_case"))
        val unsupplied = renderJob(job)
        assertTrue(unsupplied.contains("The exploration report is unavailable"))
        assertTrue(!unsupplied.contains("stored_case"))
        val actual = request(server, "GET", "/jobs/$id")
        assertEquals(200, actual.status)
        assertTrue(actual.body.decodeToString().contains("stored_case"))
        assertTrue(actual.body.decodeToString().contains("63%"))
        assertContentEquals(bytes, report.readBytes())
        for (invalid in listOf("PRIVATE_REPORT {", "x".repeat(1_048_577), "{\"confidence\":[]}", "{\"confidence\":{},\"confidence\":{}}")) {
            report.writeText(invalid)
            val response = request(server, "GET", "/jobs/$id")
            assertEquals(200, response.status)
            assertTrue(response.body.decodeToString().contains("The exploration report is unavailable"))
            assertTrue(!response.body.decodeToString().contains("PRIVATE_REPORT"))
            assertEquals(invalid, report.readBytes().decodeToString())
        }
        Files.delete(report)
        assertTrue(request(server, "GET", "/jobs/$id").body.decodeToString().contains("The exploration report is unavailable"))
        assertTrue(!report.exists())
    }

    @Test
    fun `legacy JSON read routes negotiate methods and Accept before storage access`() = withServer { server, root ->
        val id = uploadedJobId(server)
        val record = root.resolve(id).resolve("job.json")
        val reports = root.resolve(id).resolve("reports")
        decompengine.jobs.AgentProgressJournal(reports, "reconstruct").use { }
        val journal = reports.resolve(decompengine.jobs.AgentProgressJournal.FILE_NAME)
        val jobBefore = record.readBytes()
        val journalBefore = journal.readBytes()
        for (path in listOf("/api/jobs/$id", "/api/jobs/$id/events")) {
            for (accept in listOf("application/json", "application/*", "*/*", "text/html, application/json;q=0.5", "APPLICATION/JSON")) {
                val response = request(server, "GET", path, headers = mapOf("Accept" to accept))
                assertEquals(200, response.status, accept)
                assertEquals("application/json; charset=utf-8", response.contentType)
            }
            for (accept in listOf("text/html", "application/json;q=0, */*;q=1", "application/*;q=0, */*;q=1", "application/json;q=2")) {
                val response = request(server, "GET", path, headers = mapOf("Accept" to accept))
                assertEquals(406, response.status, accept)
                assertTrue(response.body.decodeToString().contains("NOT_ACCEPTABLE"))
                assertEquals("application/json; charset=utf-8", response.contentType)
            }
            val oversized = request(server, "GET", path, headers = mapOf("Accept" to "x".repeat(513)))
            assertEquals(400, oversized.status)
            assertTrue(oversized.body.decodeToString().contains("INVALID_HEADER"))
            for (method in listOf("POST", "PUT", "DELETE", "OPTIONS", "HEAD")) {
                val response = request(server, method, path, headers = mapOf("Accept" to "text/html"))
                assertEquals(405, response.status, method)
                assertEquals("GET", response.allow)
                assertEquals("application/json; charset=utf-8", response.contentType)
                assertEquals("no-store", response.cacheControl)
                if (method == "HEAD") assertTrue(response.body.isEmpty())
                else assertTrue(response.body.decodeToString().contains("METHOD_NOT_ALLOWED"))
            }
        }
        assertEquals(404, request(server, "POST", "/api/unknown", headers = mapOf("Accept" to "text/html")).status)
        assertContentEquals(jobBefore, record.readBytes())
        assertContentEquals(journalBefore, journal.readBytes())
        // A damaged record must not turn a negotiation failure into a storage read failure.
        record.writeText("PRIVATE_CORRUPTION {")
        assertEquals(405, request(server, "DELETE", "/api/jobs/$id").status)
        assertEquals(406, request(server, "GET", "/api/jobs/$id", headers = mapOf("Accept" to "text/html")).status)
        assertEquals("PRIVATE_CORRUPTION {", record.readBytes().decodeToString())
    }

    @Test
    fun `legacy JSON errors have fixed public messages and request identities`() {
        withServer { server, root ->
            val id = uploadedJobId(server)
            val record = root.resolve(id).resolve("job.json")
            val before = record.readBytes()
            val cases = listOf(
                Triple(request(server, "GET", "/api/PRIVATE_ROUTE_SENTINEL"), 404, "NOT_FOUND"),
                Triple(request(server, "GET", "/api/jobs/PRIVATE_JOB_SENTINEL"), 404, "JOB_NOT_FOUND"),
                Triple(request(server, "GET", "/api/jobs/$id/events?PRIVATE_QUERY_SENTINEL=x"), 400, "INVALID_REQUEST"),
                Triple(upload(server, "PRIVATE_FILENAME_SENTINEL", byteArrayOf(1, 2, 3), true), 400, "INVALID_UPLOAD"),
            ).toMutableList()
            assertContentEquals(before, record.readBytes())
            record.writeText("PRIVATE_STORAGE_SENTINEL { root=$root")
            val corrupted = record.readBytes()
            cases += Triple(request(server, "GET", "/api/jobs/$id"), 503, "JOB_STORAGE_UNAVAILABLE")
            assertContentEquals(corrupted, record.readBytes())
            val requestIds = mutableSetOf<String>()
            cases.forEach { (response, status, code) ->
                assertEquals(status, response.status)
                assertEquals("application/json; charset=utf-8", response.contentType)
                assertEquals("no-store", response.cacheControl)
                val body = Json.parseToJsonElement(response.body.decodeToString()).jsonObject
                assertEquals(setOf("requestId", "error"), body.keys)
                val requestId = body.getValue("requestId").toString().trim('"')
                assertEquals(requestId, response.requestId)
                assertTrue(requestIds.add(requestId))
                java.util.UUID.fromString(requestId)
                val error = body.getValue("error").jsonObject
                assertEquals(setOf("code", "message"), error.keys)
                assertEquals("\"$code\"", error.getValue("code").toString())
                listOf("PRIVATE_", root.toString(), "Exception", "<html").forEach {
                    assertTrue(!response.body.decodeToString().contains(it), it)
                }
            }
            val html = upload(server, "invalid.elf", byteArrayOf(1, 2, 3), false)
            assertEquals(400, html.status)
            assertEquals("text/html; charset=utf-8", html.contentType)
        }
    }

    @Test
    fun `legacy upload and job JSON omit private storage fields without changing persistence`() {
        withServer { server, root ->
            val uploaded = upload(server, "presentation.elf", elfFixture(), acceptJson = true)
            assertEquals(201, uploaded.status)
            val publicJob = Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject
            val id = publicJob.getValue("id").toString().trim('"')
            val record = root.resolve(id).resolve("job.json")
            val initialBytes = record.readBytes()
            val persisted = Json.parseToJsonElement(initialBytes.decodeToString()).jsonObject
            val publicKeys = setOf("id", "filename", "status", "created_at", "updated_at", "size_bytes", "metadata")
            assertEquals(publicKeys, publicJob.keys)
            publicKeys.forEach { assertEquals(persisted[it], publicJob[it], it) }
            assertTrue(persisted.containsKey("binary_path"))
            val read = request(server, "GET", "/api/jobs/$id")
            assertEquals(200, read.status)
            assertEquals(publicJob, Json.parseToJsonElement(read.body.decodeToString()))
            assertContentEquals(initialBytes, record.readBytes())

            // Old persisted diagnostics may contain secrets predating current redaction.
            val diagnostic = "PRIVATE_DIAGNOSTIC_SENTINEL root=$root env=PRIVATE_ENV_VALUE"
            decompengine.jobs.JobStore(root).updateStatus(id, "failed", diagnostic)
            val failedBytes = record.readBytes()
            val failed = request(server, "GET", "/api/jobs/$id")
            assertEquals(200, failed.status)
            val failedJob = Json.parseToJsonElement(failed.body.decodeToString()).jsonObject
            assertEquals(publicKeys, failedJob.keys)
            assertEquals("\"failed\"", failedJob.getValue("status").toString())
            listOf(uploaded, read, failed).forEach { response ->
                listOf(root.toString(), "binary_path", "status_message", "PRIVATE_DIAGNOSTIC_SENTINEL", "PRIVATE_ENV_VALUE").forEach {
                    assertTrue(!response.body.decodeToString().contains(it), it)
                }
            }
            assertTrue(failedBytes.decodeToString().contains("PRIVATE_DIAGNOSTIC_SENTINEL"))
            assertContentEquals(failedBytes, record.readBytes())
        }
    }

    @Test
    fun `missing job workflow admissions return typed safe not found responses`() {
        var executions = 0
        withServer(JobAnalyzer { _, _ -> executions++ }, JobReconstructor { _, _ -> executions++ }) { server, root ->
            for (workflow in listOf("explore", "reconstruct")) {
                val response = request(server, "POST", "/jobs/${"a".repeat(32)}/$workflow", followRedirects = false)
                assertEquals(404, response.status)
                assertTrue(response.body.decodeToString().contains("JOB_NOT_FOUND"))
                kotlin.test.assertFalse(response.body.decodeToString().contains(root.toString()))
            }
            assertEquals(0, executions)
        }
    }

    @Test
    fun `background diagnostics redact secrets before persistence and rendering`() {
        val dataDir = createTempDirectory("web-private-diagnostic-")
        val configured = "configured-provider-credential"
        val bearer = "synthetic-bearer-value"
        val password = "synthetic-password-value"
        val server = UploadServer("127.0.0.1", 0, dataDir,
            analyzer = JobAnalyzer { _, _ -> error("Provider refused $configured; Bearer $bearer; password=$password <script>bad</script>") },
            reconstructor = JobReconstructor { _, _ -> error("z".repeat(17000) + configured) },
            executor = Executor { it.run() }, sensitiveValues = listOf(configured))
        server.start()
        try {
            val invalid = request(server, "GET", "/jobs/$configured")
            assertEquals(404, invalid.status)
            assertTrue(!invalid.body.decodeToString().contains(configured))
            assertTrue(invalid.body.decodeToString().contains("JOB_NOT_FOUND"))
            val uploaded = upload(server, "diagnostic.elf", elfFixture(), acceptJson = true)
            val id = Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject["id"].toString().trim('"')
            assertEquals(303, request(server, "POST", "/jobs/$id/explore", followRedirects = false).status)
            val persisted = dataDir.resolve(id).resolve("job.json").readBytes().decodeToString()
            val api = request(server, "GET", "/api/jobs/$id").body.decodeToString()
            val page = request(server, "GET", "/jobs/$id").body.decodeToString()
            listOf(persisted, page).forEach { text ->
                listOf(configured, bearer, password).forEach { assertTrue(!text.contains(it)) }
                assertTrue(text.contains("[redacted]"))
            }
            listOf(configured, bearer, password, "status_message", "binary_path").forEach {
                assertTrue(!api.contains(it))
            }
            assertTrue(!page.contains("<script>bad</script>"))
            assertEquals(303, request(server, "POST", "/jobs/$id/reconstruct", followRedirects = false).status)
            val job = decompengine.jobs.JobStore(dataDir).get(id)
            assertEquals("failed", job.status)
            assertEquals("[oversized text omitted]", job.statusMessage)
        } finally {
            server.stop()
        }
    }

    @Test
    fun `dashboard keeps malformed jobs visible and detail returns a safe storage diagnostic`() {
        withServer { server, root ->
            val created = upload(server, "damaged.elf", elfFixture(), acceptJson = true)
            val jobId = Json.parseToJsonElement(created.body.decodeToString()).jsonObject.getValue("id").toString().trim('"')
            root.resolve(jobId).resolve("job.json").writeText("PRIVATE_CORRUPTION_SENTINEL {")
            val dashboard = request(server, "GET", "/")
            val detail = request(server, "GET", "/jobs/$jobId")
            assertEquals(200, dashboard.status)
            assertTrue(dashboard.body.decodeToString().contains(jobId))
            assertTrue(dashboard.body.decodeToString().contains("CORRUPT_LEGACY_JOB"))
            assertEquals(503, detail.status)
            assertTrue(detail.body.decodeToString().contains("verified backup"))
            kotlin.test.assertFalse(detail.body.decodeToString().contains("PRIVATE_CORRUPTION_SENTINEL"))
            kotlin.test.assertFalse(detail.body.decodeToString().contains(root.toString()))
        }
    }

    @Test
    fun `rejected admission can be retried without a stale job reservation`() {
        val reject = java.util.concurrent.atomic.AtomicBoolean(true)
        var calls = 0
        val server = UploadServer("127.0.0.1", 0, createTempDirectory("web-admission-retry-"),
            analyzer = JobAnalyzer { _, _ -> calls++ },
            executor = Executor { task ->
                if (reject.getAndSet(false)) throw java.util.concurrent.RejectedExecutionException("private worker detail")
                task.run()
            })
        server.start()
        try {
            val uploaded = upload(server, "retry.elf", elfFixture(), acceptJson = true)
            val id = Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject["id"].toString().trim('"')
            val rejected = request(server, "POST", "/jobs/$id/explore", followRedirects = false)
            assertEquals(503, rejected.status)
            assertTrue(!rejected.body.decodeToString().contains("private worker detail"))
            assertEquals(0, calls)
            assertEquals(303, request(server, "POST", "/jobs/$id/explore", followRedirects = false).status)
            assertEquals(1, calls)
            val job = Json.parseToJsonElement(request(server, "GET", "/api/jobs/$id").body.decodeToString()).jsonObject
            assertEquals("complete", job["status"].toString().trim('"'))
        } finally {
            server.stop()
        }
    }

    @Test
    fun `owned workers bound pending jobs reject overflow and discard queued work at shutdown`() {
        val dataDir = createTempDirectory("web-bounded-jobs-")
        val started = java.util.concurrent.CountDownLatch(2)
        val stopped = java.util.concurrent.CountDownLatch(2)
        val release = java.util.concurrent.CountDownLatch(1)
        val invocations = java.util.concurrent.atomic.AtomicInteger()
        val server = UploadServer("127.0.0.1", 0, dataDir, analyzer = JobAnalyzer { _, _ ->
            invocations.incrementAndGet()
            started.countDown()
            try {
                release.await()
            } finally {
                stopped.countDown()
            }
        })
        server.start()
        val ids = mutableListOf<String>()
        var closed = false
        try {
            repeat(35) { index ->
                val uploaded = upload(server, "queued-$index.elf", elfFixture(), acceptJson = true)
                ids += Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject["id"].toString().trim('"')
            }
            ids.take(2).forEach { id ->
                assertEquals(303, request(server, "POST", "/jobs/$id/explore", followRedirects = false).status)
            }
            assertTrue(started.await(5, java.util.concurrent.TimeUnit.SECONDS))
            ids.subList(2, 34).forEach { id ->
                assertEquals(303, request(server, "POST", "/jobs/$id/explore", followRedirects = false).status)
            }
            assertEquals(409, request(server, "POST", "/jobs/${ids[2]}/reconstruct", followRedirects = false).status)
            repeat(2) {
                val overflow = request(server, "POST", "/jobs/${ids.last()}/explore", followRedirects = false)
                assertEquals(503, overflow.status)
                assertEquals("1", overflow.retryAfter)
            }
            assertEquals(200, request(server, "GET", "/api/jobs/${ids[0]}").status)
            assertEquals(2, invocations.get())
            server.stop()
            closed = true
            assertTrue(stopped.await(5, java.util.concurrent.TimeUnit.SECONDS))
            val store = decompengine.jobs.JobStore(dataDir)
            ids.subList(2, 34).forEach { id ->
                val job = store.get(id)
                assertEquals("failed", job.status)
                assertEquals("Server stopped before the operation started", job.statusMessage)
            }
            assertEquals("failed", store.get(ids.last()).status)
            assertEquals(2, invocations.get())
        } finally {
            release.countDown()
            if (!closed) server.stop()
        }
    }

    @Test
    fun `job event endpoint and refresh render the persisted bounded stream`() {
        withServer { server, dataDir ->
            val uploaded = upload(server, "progress.elf", elfFixture(), acceptJson = true)
            val jobId = Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject["id"].toString().trim('"')
            val reports = dataDir.resolve(jobId).resolve("reports")
            decompengine.jobs.AgentProgressJournal(reports, "reconstruction").use { journal ->
                journal.phase(decompengine.agent.AgentWorkflowPhase.BUILD_VALIDATING, "module-1")
                journal.runState(decompengine.agent.AgentWorkflowRunObservation("run_00000001",
                    decompengine.agent.AgentWorkflowPhase.PROVISIONAL, "revision-one"))
                journal.runState(decompengine.agent.AgentWorkflowRunObservation("run_00000001",
                    decompengine.agent.AgentWorkflowPhase.EXHAUSTED, "revision-one"))
                val task = journal.beginTask("thought-task", decompengine.agent.AgentExecutionRequest(
                    "fixture", listOf(decompengine.agent.AgentWorkspaceRoot("project", reports)),
                    accessPolicy = decompengine.agent.AgentAccessPolicy(emptyList())))
                task.event(decompengine.agent.AgentMessageEvent(0, "thought", decompengine.agent.AgentMessageRole.THOUGHT,
                    "checking fixture", completed = true))
                task.event(decompengine.agent.AgentContextUsageEvent(1, Long.MAX_VALUE, Long.MAX_VALUE, 0.125, "USD"))
                task.complete(decompengine.agent.AgentExecutionReceipt(
                    decompengine.agent.AgentExecutionRequestBinding.capture(decompengine.agent.AgentExecutionRequest(
                        "fixture", listOf(decompengine.agent.AgentWorkspaceRoot("project", reports)),
                        accessPolicy = decompengine.agent.AgentAccessPolicy(emptyList()))),
                    decompengine.agent.AgentExecutionOutcome.Returned(decompengine.agent.AgentExecutionResult(
                        decompengine.agent.AgentStopReason.COMPLETED,
                        usage = decompengine.agent.AgentUsage(cachedInputTokens = 0, wallClock = java.time.Duration.ofMillis(125))))))
            }
            val response = request(server, "GET", "/api/jobs/$jobId/events")
            assertEquals(200, response.status)
            assertTrue(response.body.decodeToString().contains("build_validating"))
            assertTrue(response.body.decodeToString().contains("\"displayOnly\":true"))
            assertTrue(response.body.decodeToString().contains("\"workflowRunId\":\"run_00000001\""))
            val page = request(server, "GET", "/jobs/$jobId").body.decodeToString()
            assertTrue(page.contains("Agent progress"))
            assertTrue(page.contains("build_validating"))
            assertTrue(page.contains("Accepted revisions are recorded separately"))
            val rows = page.substringAfter("<ol id=\"agent-event-list\"").substringBefore("</ol>")
            assertTrue(rows.contains("message · thought"))
            assertTrue(rows.contains("cached input tokens: 0"))
            assertTrue(rows.contains("elapsed: PT0.125S"))
            assertTrue(rows.contains("context used: 9223372036854775807"))
            assertTrue(rows.contains("reported cost: 0.125"))
            assertTrue(rows.contains("run_00000001"))
            assertTrue(rows.contains("revision-one"))
            assertTrue(rows.contains("provisional") && rows.contains("exhausted"))
            assertTrue(!rows.contains("accepted source"))
        }
    }

    @Test
    fun `legacy progress withholds uncertified prose and unknown fields in JSON and HTML`() = withServer { server, root ->
        val id = uploadedJobId(server)
        val reports = root.resolve(id).resolve("reports").createDirectories()
        val journal = reports.resolve(decompengine.jobs.AgentProgressJournal.FILE_NAME)
        val roles = listOf("thought", "system", "assistant", "unknown")
        val events = roles.mapIndexed { index, role ->
            """{"sequence":$index,"kind":"message","role":"$role","text":"PRIVATE_MESSAGE_$role","textOmitted":false,"contentSha256":"${"a".repeat(64)}","futureField":{"nested":"PRIVATE_UNKNOWN"}}"""
        } + """{"sequence":4,"kind":"plan","entryCount":1,"entries":[{"idSha256":"${"b".repeat(64)}","status":"pending","text":"PRIVATE_PLAN"}]}""" +
            """{"sequence":5,"kind":"tool","text":"PRIVATE_TOOL","path":"/PRIVATE_HOST_ROOT/input","inputTokens":9223372036854775807,"taskId":{"nested":"PRIVATE_NESTED_LABEL"}}"""
        journal.writeText("""{"schemaVersion":1,"displayOnly":true,"nextSequence":6,"queueDropped":0,"historyDropped":0,"truncated":false,"futureRoot":"PRIVATE_ROOT","events":[${events.joinToString(",") }]}""")
        val original = journal.readBytes()
        val response = request(server, "GET", "/api/jobs/$id/events")
        assertEquals(200, response.status)
        val projected = Json.parseToJsonElement(response.body.decodeToString()).jsonObject
        assertEquals("1", projected.getValue("presentationOmittedFields").toString())
        val rows = projected.getValue("events") as kotlinx.serialization.json.JsonArray
        assertEquals(6, rows.size)
        rows.take(4).forEachIndexed { index, item ->
            val event = item.jsonObject
            assertEquals(index.toString(), event.getValue("sequence").toString())
            assertEquals("true", event.getValue("textOmitted").toString())
            assertEquals("2", event.getValue("presentationOmittedFields").toString())
            assertEquals("\"${"a".repeat(64)}\"", event.getValue("contentSha256").toString())
        }
        assertEquals("1", rows[4].jsonObject.getValue("entryCount").toString())
        assertEquals("9223372036854775807", rows[5].jsonObject.getValue("inputTokens").toString())
        val page = request(server, "GET", "/jobs/$id")
        assertEquals(200, page.status)
        assertTrue(page.body.decodeToString().contains("does not certify public visibility"))
        assertTrue(page.body.decodeToString().contains("Some event fields withheld"))
        listOf(response, page).forEach { assertTrue(!it.body.decodeToString().contains("PRIVATE_")) }
        assertContentEquals(original, journal.readBytes())
    }

    @Test
    fun `HTML progress renders only the supplied snapshot rather than reopening the journal`() = withServer { server, root ->
        val id = uploadedJobId(server)
        val reports = root.resolve(id).resolve("reports").createDirectories()
        val snapshot = Json.parseToJsonElement("""{"schemaVersion":1,"displayOnly":true,"nextSequence":1,"queueDropped":0,"historyDropped":0,"truncated":false,"events":[{"sequence":0,"kind":"workflow_phase","phase":"supplied_snapshot_phase"}]}""").jsonObject
        val path = reports.resolve(decompengine.jobs.AgentProgressJournal.FILE_NAME)
        path.writeText(snapshot.toString().replace("supplied_snapshot_phase", "stored_snapshot_phase"))
        val before = path.readBytes()
        val job = decompengine.jobs.JobStore(root).get(id)
        val supplied = renderJob(job, progressSnapshot = snapshot)
        assertTrue(supplied.contains("supplied_snapshot_phase"))
        assertTrue(!supplied.contains("stored_snapshot_phase"))
        val absent = renderJob(job)
        assertTrue(absent.contains("Retained progress is unavailable"))
        assertTrue(!absent.contains("stored_snapshot_phase"))
        assertContentEquals(before, path.readBytes())
    }

    @Test
    fun `legacy progress distinguishes unavailable journals from a persisted empty journal`() = withServer { server, root ->
        val id = uploadedJobId(server)
        val record = root.resolve(id).resolve("job.json")
        val original = record.readBytes()
        val reports = root.resolve(id).resolve("reports")
        val journal = reports.resolve(decompengine.jobs.AgentProgressJournal.FILE_NAME)
        fun unavailable() {
            val response = request(server, "GET", "/api/jobs/$id/events")
            assertEquals(503, response.status)
            assertEquals("application/json; charset=utf-8", response.contentType)
            val body = Json.parseToJsonElement(response.body.decodeToString()).jsonObject
            assertEquals("\"PROGRESS_UNAVAILABLE\"", body.getValue("error").jsonObject.getValue("code").toString())
            listOf("PRIVATE_", root.toString(), "nextSequence", "events").forEach {
                assertTrue(!response.body.decodeToString().contains(it), it)
            }
            val page = request(server, "GET", "/jobs/$id")
            assertEquals(200, page.status)
            assertTrue(page.body.decodeToString().contains("Retained progress is unavailable"))
            assertTrue(!page.body.decodeToString().contains("PRIVATE_"))
            assertContentEquals(original, record.readBytes())
        }
        unavailable()
        assertTrue(!journal.exists())
        reports.createDirectories()
        for (contents in listOf("PRIVATE_DAMAGED_JOURNAL {", "x".repeat(2 * 1024 * 1024 + 1))) {
            journal.writeText(contents)
            val bytes = journal.readBytes()
            unavailable()
            assertContentEquals(bytes, journal.readBytes())
        }
        val empty = """{"schemaVersion":1,"displayOnly":true,"nextSequence":0,"queueDropped":0,"historyDropped":0,"truncated":false,"events":[]}"""
        journal.writeText(empty)
        val response = request(server, "GET", "/api/jobs/$id/events")
        assertEquals(200, response.status)
        assertEquals(Json.parseToJsonElement(empty), Json.parseToJsonElement(response.body.decodeToString()))
        val emptyPage = request(server, "GET", "/jobs/$id")
        assertTrue(emptyPage.body.decodeToString().contains("The retained journal currently contains no events."))
        assertTrue(!emptyPage.body.decodeToString().contains("Retained progress is unavailable"))
        assertEquals(empty, journal.readBytes().decodeToString())
        assertContentEquals(original, record.readBytes())
    }

    @Test
    fun `legacy event reads reject unknown attempt identities and extra query parameters`() = withServer { server, _ ->
        val id = uploadedJobId(server)
        assertEquals(404, request(server, "GET", "/api/jobs/$id/events?runId=run_missing").status)
        assertEquals(400, request(server, "GET", "/api/jobs/$id/events?runId=run_missing&other=value").status)
    }

    @Test
    fun `upload page has ELF form`() {
        withServer { server, _ ->
            val response = request(server, "GET", "/")

            assertEquals(200, response.status)
            assertTrue(response.body.decodeToString().contains("multipart/form-data"))
            assertTrue(response.body.decodeToString().contains("name=\"binary\""))
            assertTrue(response.body.decodeToString().contains("Binary reconstruction workbench"))
            assertTrue(response.body.decodeToString().contains("/assets/app.css"))
        }
    }

    @Test
    fun `dashboard lists uploaded jobs`() {
        withServer { server, _ ->
            upload(server, "dashboard.elf", elfFixture(), acceptJson = true)

            val page = request(server, "GET", "/")

            assertEquals(200, page.status)
            assertTrue(page.body.decodeToString().contains("Recent jobs"))
            assertTrue(page.body.decodeToString().contains("dashboard.elf"))
            assertTrue(page.body.decodeToString().contains("Uploaded"))
        }
    }

    @Test
    fun `web UI uploads ELF and returns job JSON`() {
        withServer { server, dataDir ->
            val response = upload(server, "fixture.elf", elfFixture(), acceptJson = true)

            assertEquals(201, response.status)
            val job = Json.parseToJsonElement(response.body.decodeToString()).jsonObject
            val jobId = job["id"].toString().trim('"')
            assertEquals("fixture.elf", job["filename"].toString().trim('"'))
            assertEquals("uploaded", job["status"].toString().trim('"'))
            assertEquals("ELF64", job["metadata"]!!.jsonObject["format"].toString().trim('"'))
            assertEquals("x86-64", job["metadata"]!!.jsonObject["machine"].toString().trim('"'))
            assertTrue(dataDir.resolve(jobId).resolve("input.elf").readBytes().startsWith(byteArrayOf(0x7f, 0x45, 0x4c, 0x46)))
            assertTrue(dataDir.resolve(jobId).resolve("job.json").exists())
        }
    }

    @Test
    fun `job state page shows status metadata and repair iteration history`() {
        withServer { server, dataDir ->
            val upload = upload(server, "fixture.elf", elfFixture(), acceptJson = true)
            val job = Json.parseToJsonElement(upload.body.decodeToString()).jsonObject
            val jobId = job["id"].toString().trim('"')
            val reportsDir = dataDir.resolve(jobId).resolve("reports").createDirectories()
            reportsDir.resolve("repair_history.json").writeText(
                """
                {
                  "iterations": [
                    {
                      "index": 1,
                      "failureKind": "behavior",
                      "summary": "match observed stdout",
                      "succeeded": true,
                      "before": {"kind":"behavior","summary":"one mismatch","artifactPath":"before.diff.json"},
                      "after": {"kind":"valid","summary":"all cases match","artifactPath":"after.behavior.json"},
                      "retainedRegressionIds": ["hello_default"]
                    }
                  ]
                }
                """.trimIndent(),
            )

            val page = request(server, "GET", "/jobs/$jobId")
            val body = page.body.decodeToString()

            assertEquals(200, page.status)
            assertTrue(body.contains("uploaded"))
            assertTrue(body.contains("fixture.elf"))
            assertTrue(body.contains("ELF64"))
            assertTrue(body.contains("x86-64"))
            assertTrue(body.contains("Repair History"))
            assertTrue(body.contains("Iteration 1"))
            assertTrue(body.contains("match observed stdout"))
            assertTrue(body.contains("hello_default"))
            assertTrue(body.contains("behavior — passed"))
            assertTrue(body.contains("Before:"))
            assertTrue(body.contains("one mismatch"))
            assertTrue(body.contains("After:"))
            assertTrue(body.contains("all cases match"))
        }
    }

    @Test
    fun `upload rejects non-ELF content`() {
        withServer { server, _ ->
            val response = upload(server, "not-elf.bin", "not an elf".toByteArray(), acceptJson = false)

            assertEquals(400, response.status)
            assertTrue(response.body.decodeToString().contains("ELF"))
        }
    }

    @Test
    fun `GUI launches analysis renders evidence and downloads artifacts`() {
        val analyzer = JobAnalyzer { job, reportsDir ->
            assertEquals("analyzing", job.status)
            reportsDir.resolve("exploration.json").writeText(
                """
                {
                  "candidateCount": 2,
                  "coverageIncreased": true,
                  "baselineOutputSignatures": 1,
                  "expandedOutputSignatures": 2,
                  "newOutputSignatures": ["2:4152475f5345435245540a:"],
                  "angr": {"argvStates":2,"stdinStates":2,"argvSteps":10,"stdinSteps":12},
                  "confidence": {
                    "score": 0.625,
                    "inputCount": 2,
                    "sourceCount": 2,
                    "outputSignatureCount": 2,
                    "newOutputSignatureCount": 1,
                    "sandboxed": true,
                    "networkIsolated": true
                  },
                  "candidates": [
                    {"id":"seed_default","source":"SEED","args":[],"stdinHex":""},
                    {"id":"angr_secret","source":"ANGR","args":["secret"],"stdinHex":""}
                  ],
                  "observations": [
                    {"candidateId":"seed_default","signature":"0:44454641554c540a:","exitCode":0,"stdoutHex":"44454641554c540a","stderrHex":"","networkIsolated":true},
                    {"candidateId":"angr_secret","signature":"2:4152475f5345435245540a:","exitCode":2,"stdoutHex":"4152475f5345435245540a","stderrHex":"","networkIsolated":true}
                  ]
                }
                """.trimIndent(),
            )
        }
        withServer(analyzer) { server, _ ->
            val upload = upload(server, "branching.elf", elfFixture(), acceptJson = true)
            val job = Json.parseToJsonElement(upload.body.decodeToString()).jsonObject
            val jobId = job["id"].toString().trim('"')

            val launch = request(server, "POST", "/jobs/$jobId/explore", followRedirects = false)
            val page = request(server, "GET", "/jobs/$jobId")
            val api = request(server, "GET", "/api/jobs/$jobId")
            val artifact = request(server, "GET", "/jobs/$jobId/artifacts/reports/exploration.json")

            assertEquals(303, launch.status)
            assertEquals("complete", Json.parseToJsonElement(api.body.decodeToString()).jsonObject["status"].toString().trim('"'))
            val html = page.body.decodeToString()
            assertTrue(html.contains("Exploration report"))
            assertTrue(html.contains("63%"))
            assertTrue(html.contains("angr_secret"))
            assertTrue(html.contains("ARG_SECRET↵"))
            assertTrue(html.contains("Artifacts"))
            assertEquals(200, artifact.status)
            assertTrue(artifact.body.decodeToString().contains("\"candidateCount\": 2"))
        }
    }

    @Test
    fun `GUI launches reconstruction browses escaped source and rejects an unverified archive`() {
        val reconstructor = JobReconstructor { job, reportsDir ->
            assertEquals("analyzing", job.status)
            val tree = reportsDir.resolve("source-tree")
            tree.resolve("src/modules").createDirectories()
            tree.resolve("reports").createDirectories()
            tree.resolve("src/modules/core.c").writeText("int core(void) { /* <script>alert(1)</script> */ return 0; }\n")
            tree.resolve("Makefile").writeText("all:\n\t@true\n")
            tree.resolve("reports/confidence.json").writeText("{\"projectScore\":0.75,\"modules\":[{\"id\":\"core\",\"score\":0.8}]}")
            writeManifest(tree, listOf("src/modules/core.c", "Makefile", "reports/confidence.json"))
            reportsDir.resolve("reconstruction_progress.json").writeText("{\"phase\":\"modules\",\"completed\":2,\"total\":4,\"module\":\"core\"}")
            reportsDir.resolve("source-tree.zip").writeText("archive")
        }
        withServer(reconstructor = reconstructor) { server, _ ->
            val upload = upload(server, "archive.elf", elfFixture(), acceptJson = true)
            val jobId = Json.parseToJsonElement(upload.body.decodeToString()).jsonObject["id"].toString().trim('"')

            val launch = request(server, "POST", "/jobs/$jobId/reconstruct", followRedirects = false)
            val page = request(server, "GET", "/jobs/$jobId")
            val source = request(server, "GET", "/jobs/$jobId/source/src/modules/core.c")
            val archive = request(server, "GET", "/jobs/$jobId/artifacts/reports/source-tree.zip")
            val traversal = request(server, "GET", "/jobs/$jobId/source/%2e%2e%2Foutside.c")

            assertEquals(303, launch.status)
            assertTrue(page.body.decodeToString().contains("Archival source tree"))
            assertTrue(page.body.decodeToString().contains("src/modules/core.c"))
            assertTrue(page.body.decodeToString().contains("75%"))
            assertTrue(page.body.decodeToString().contains("2 / 4 modules"))
            assertTrue(!page.body.decodeToString().contains("Download verified source archive"))
            assertEquals(200, source.status)
            assertTrue(source.body.decodeToString().contains("&lt;script&gt;"))
            assertTrue(!source.body.decodeToString().contains("<script>alert"))
            assertTrue(source.body.decodeToString().contains("fn_1000"))
            assertTrue(source.body.decodeToString().contains("80%"))
            assertEquals(400, archive.status)
            assertEquals(400, traversal.status)
        }
    }

    @Test
    fun `artifact and source routes reject final file and parent directory indirection`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val reports = dataDir.resolve("$jobId/reports").createDirectories()
            val external = dataDir.resolve("outside").createDirectories()
            external.resolve("secret.c").writeText("outside-boundary-marker")
            Files.createSymbolicLink(reports.resolve("source-tree.zip"), external.resolve("secret.c"))
            Files.createSymbolicLink(reports.resolve("source-tree"), external)
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId/artifacts/reports/source-tree.zip"))
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId/source/secret.c"))
            Files.delete(reports.resolve("source-tree"))
            val tree = reports.resolve("source-tree").createDirectories()
            Files.createSymbolicLink(tree.resolve("secret.c"), external.resolve("secret.c"))
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId/source/secret.c"))
        }
    }

    @Test
    fun `routes reject a substituted job directory instead of following its reports`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val original = dataDir.resolve(jobId)
            original.resolve("reports/source-tree").createDirectories()
            original.resolve("reports/source-tree/source.c").writeText("outside-boundary-marker")
            val moved = dataDir.resolve("moved-job")
            Files.move(original, moved)
            Files.createSymbolicLink(original, moved)
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId/source/source.c"))
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId/artifacts/reports/source-tree/source.c"))
            assertRejectedWithoutMarker(request(server, "GET", "/jobs/$jobId"))
        }
    }

    @Test
    fun `source and archive response reads reject oversized sparse files`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val reports = dataDir.resolve("$jobId/reports").createDirectories()
            val tree = reports.resolve("source-tree").createDirectories()
            val source = tree.resolve("src/modules").createDirectories().resolve("large.c")
            val archive = reports.resolve("source-tree.zip")
            sparseFile(source, 4L * 1024 * 1024 + 1)
            sparseFile(archive, 64L * 1024 * 1024 + 1)
            writeManifest(tree, listOf("src/modules/large.c"))
            assertEquals(400, request(server, "GET", "/jobs/$jobId/source/src/modules/large.c").status)
            assertEquals(400, request(server, "GET", "/jobs/$jobId/artifacts/reports/source-tree.zip").status)
        }
    }

    @Test
    fun `source rendering never reads linked or oversized provenance metadata`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val tree = dataDir.resolve("$jobId/reports/source-tree").createDirectories()
            tree.resolve("source.c").writeText("int source(void) { return 0; }\n")
            val external = dataDir.resolve("outside.json")
            external.writeText("""{"files":[{"path":"source.c","generator":"outside-boundary-marker","entityIds":[]}]}""")
            Files.createSymbolicLink(tree.resolve("source_tree_manifest.json"), external)
            val linked = request(server, "GET", "/jobs/$jobId/source/source.c")
            assertRejectedWithoutMarker(linked)
            Files.delete(tree.resolve("source_tree_manifest.json"))
            sparseFile(tree.resolve("source_tree_manifest.json"), 1024L * 1024 + 1)
            assertEquals(400, request(server, "GET", "/jobs/$jobId/source/source.c").status)
        }
    }

    @Test
    fun `source responses reject malformed UTF8 without replacement decoding`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val tree = dataDir.resolve("$jobId/reports/source-tree").createDirectories()
            tree.resolve("src/modules").createDirectories().resolve("invalid.c").writeBytes(byteArrayOf(0xc3.toByte(), 0x28))
            writeManifest(tree, listOf("src/modules/invalid.c"))
            assertEquals(400, request(server, "GET", "/jobs/$jobId/source/src/modules/invalid.c").status)
        }
    }

    @Test
    fun `artifact routes reject noncanonical paths and nonregular targets`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            dataDir.resolve("$jobId/reports/directory.json").createDirectories()
            for (relative in listOf("reports/directory.json", "reports/%2e%2e%2fjob.json", "reports%5cfile.json", "reports/file%0a.json")) {
                val response = request(server, "GET", "/jobs/$jobId/artifacts/$relative")
                assertTrue(response.status in 400..499, "unsafe artifact path returned ${response.status}: $relative")
            }
        }
    }

    @Test
    fun `source roles and text kinds come from an admitted alternate profile not suffixes`() {
        val profile = ReconstructionProfile(
            schemaVersion = ReconstructionProfile.CURRENT_SCHEMA_VERSION,
            id = "web-alternate-text-v1",
            layout = ProjectLayoutProfile(ProjectLayoutProfile.CURRENT_SCHEMA_VERSION, listOf(
                ProjectFileDeclaration("text", "units/core.rs", setOf(ProjectFileRole.VIEWABLE, ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("hidden", "private/hidden.c", setOf(ProjectFileRole.EVIDENCE), ProjectContentKind.UTF8_TEXT),
                ProjectFileDeclaration("binary", "units/binary.c", setOf(ProjectFileRole.VIEWABLE), ProjectContentKind.BINARY),
            )),
            budgets = GeneratedCMakeReconstructionProfile.descriptor.budgets,
        )
        withServer(profiles = listOf(profile)) { server, dataDir ->
            val jobId = uploadedJobId(server)
            val tree = dataDir.resolve("$jobId/reports/source-tree").createDirectories()
            tree.resolve("units").createDirectories()
            tree.resolve("private").createDirectories()
            tree.resolve("units/core.rs").writeText("pub fn core() -> u32 { 7 }\n")
            tree.resolve("private/hidden.c").writeText("not admitted for source viewing")
            tree.resolve("units/binary.c").writeBytes(byteArrayOf(0, 1, 2))
            tree.resolve("unlisted.c").writeText("not declared")
            writeManifest(tree, listOf("units/core.rs", "private/hidden.c", "units/binary.c"), profile)
            val text = request(server, "GET", "/jobs/$jobId/source/units/core.rs")
            assertEquals(200, text.status)
            assertTrue(text.body.decodeToString().contains("pub fn core()"))
            for (relative in listOf("private/hidden.c", "units/binary.c", "unlisted.c")) {
                assertEquals(400, request(server, "GET", "/jobs/$jobId/source/$relative").status)
            }
            val page = request(server, "GET", "/jobs/$jobId").body.decodeToString()
            assertTrue(page.contains("/source/units/core.rs"))
            assertTrue(!page.contains("/source/private/hidden.c"))
            assertTrue(!page.contains("/source/units/binary.c"))
            tree.resolve("source_tree_manifest.json").writeText(
                Files.readString(tree.resolve("source_tree_manifest.json")).replace(profile.sha256, "0".repeat(64)),
            )
            assertEquals(400, request(server, "GET", "/jobs/$jobId/source/units/core.rs").status)
        }
    }

    @Test
    fun `changed source input and same-byte source indirection cannot reuse manifest evidence`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val tree = dataDir.resolve("$jobId/reports/source-tree").createDirectories()
            val source = tree.resolve("src/modules").createDirectories().resolve("core.c")
            val original = "int core(void) { return 7; }\n"
            source.writeText(original)
            writeManifest(tree, listOf("src/modules/core.c"))
            val route = "/jobs/$jobId/source/src/modules/core.c"
            assertEquals(200, request(server, "GET", route).status)
            source.writeText(original.replace("7", "8"))
            assertEquals(400, request(server, "GET", route).status)
            assertTrue(request(server, "GET", "/jobs/$jobId").body.decodeToString().contains("Source-tree evidence is unavailable"))
            source.writeText(original)
            val outside = dataDir.resolve("same-byte-copy.c")
            outside.writeText(original)
            Files.delete(source)
            Files.createSymbolicLink(source, outside)
            assertTrue(request(server, "GET", route).status in 400..499)
            Files.delete(source)
            source.writeText(original)
            dataDir.resolve("$jobId/input.elf").writeBytes(elfFixture() + byteArrayOf(1))
            assertEquals(400, request(server, "GET", route).status)
        }
    }

    @Test
    fun `verified archive links pin bytes and reject stale source build and archive identities`() {
        withServer { server, dataDir ->
            val jobId = uploadedJobId(server)
            val reports = dataDir.resolve("$jobId/reports").createDirectories()
            val tree = reports.resolve("source-tree")
            val manifest = SourceTreeGenerator.generate(RecoveredProgramModel(
                inputSha256 = digest(elfFixture()),
                functions = listOf(RecoveredFunction("fn_1000", "core", 0x1000uL, "int core(void)")),
            ), tree)
            assertEquals(0, MakeProjectBuilder.build(tree).returnCode)
            val archivePath = reports.resolve("source-tree.zip")
            val first = ArchivalPackager.create(tree, archivePath)
            val firstBytes = archivePath.readBytes()
            val download = "/jobs/$jobId/artifacts/reports/source-tree.zip"
            val pinned = "$download?sha256=${first.archiveSha256}"
            val page = request(server, "GET", "/jobs/$jobId").body.decodeToString()
            assertTrue(page.contains("Download verified source archive"))
            assertTrue(page.contains(pinned))
            val initial = request(server, "GET", pinned)
            assertEquals(200, initial.status)
            assertContentEquals(firstBytes, initial.body)
            assertEquals(first.archiveSha256, digest(initial.body))
            assertEquals("\"${first.archiveSha256}\"", initial.etag)
            val implementation = manifest.files.first { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            val sourceRoute = "/jobs/$jobId/source/${implementation.path}"
            assertTrue(request(server, "GET", sourceRoute).body.decodeToString().contains("Current build identity verified"))

            var deep = tree.resolve("unarchived-depth")
            repeat(31) { deep = Files.createDirectory(deep).resolve("nested") }
            assertEquals(400, request(server, "GET", pinned).status)
            Files.walk(tree.resolve("unarchived-depth")).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::delete)
            }

            val extra = tree.resolve("src/extra.c")
            extra.writeText("int extra(void) { return 1; }\n")
            assertEquals(400, request(server, "GET", pinned).status)
            assertTrue(!request(server, "GET", "/jobs/$jobId").body.decodeToString().contains("Download verified source archive"))
            Files.delete(extra)

            val executable = tree.resolve("build/reconstructed")
            val executableBytes = executable.readBytes()
            executable.writeBytes(executableBytes + byteArrayOf(1))
            assertEquals(400, request(server, "GET", pinned).status)
            assertTrue(request(server, "GET", sourceRoute).body.decodeToString().contains("Current build verification is unavailable"))
            executable.writeBytes(executableBytes)
            assertEquals(200, request(server, "GET", pinned).status)
            val movedExecutable = reports.resolve("saved-executable")
            Files.move(executable, movedExecutable)
            Files.createSymbolicLink(executable, movedExecutable)
            assertTrue(request(server, "GET", pinned).status in 400..499)
            Files.delete(executable)
            Files.move(movedExecutable, executable)

            val contract = tree.resolve("reports/build_contract.json")
            val contractBytes = contract.readBytes()
            contract.writeBytes(contractBytes + "\n".toByteArray())
            assertEquals(400, request(server, "GET", pinned).status)
            contract.writeBytes(contractBytes)

            tree.resolve("notes.txt").writeText("additional archived context\n")
            val second = ArchivalPackager.create(tree, archivePath)
            assertNotEquals(first.archiveSha256, second.archiveSha256)
            assertEquals(400, request(server, "GET", pinned).status)
            val updated = request(server, "GET", "$download?sha256=${second.archiveSha256}")
            assertEquals(200, updated.status)
            assertEquals(second.archiveSha256, digest(updated.body))

            val marker = "Reconstructed archival source tree".toByteArray()
            val markerOffset = updated.body.indices.first { offset ->
                offset + marker.size <= updated.body.size && marker.indices.all { updated.body[offset + it] == marker[it] }
            }
            val corrupted = updated.body.clone()
            corrupted[markerOffset] = 'X'.code.toByte()
            archivePath.writeBytes(corrupted)
            val invalid = request(server, "GET", download)
            assertEquals(400, invalid.status)
            assertTrue(invalid.body.decodeToString().contains("source archive ZIP is invalid"))
            archivePath.writeBytes(updated.body)

            val copy = reports.resolve("copy.zip")
            Files.move(archivePath, copy)
            Files.createSymbolicLink(archivePath, copy)
            assertTrue(request(server, "GET", download).status in 400..499)
            Files.delete(archivePath)
            archivePath.writeText("not an archive")
            assertEquals(400, request(server, "GET", download).status)
            assertEquals(400, request(server, "GET", "$download?sha256=invalid").status)
            assertEquals(400, request(server, "GET", "$pinned&sha256=${first.archiveSha256}").status)
        }
    }

    private fun uploadedJobId(server: UploadServer): String =
        Json.parseToJsonElement(upload(server, "boundary.elf", elfFixture(), acceptJson = true).body.decodeToString())
            .jsonObject.getValue("id").toString().trim('"')

    private fun writeManifest(
        tree: Path,
        paths: List<String>,
        profile: ReconstructionProfile = GeneratedCMakeReconstructionProfile.descriptor,
    ) {
        val manifest = SourceTreeManifest(
            profileId = profile.id,
            profileSha256 = profile.sha256,
            inputSha256 = digest(elfFixture()),
            files = paths.map { relative ->
                val declaration = profile.layout.declarationForPath(relative)
                GeneratedFileEvidence(
                    path = relative,
                    sha256 = digest(tree.resolve(relative).readBytes()),
                    generator = "llm",
                    entityIds = listOf("fn_1000"),
                    acceptedImplementation = if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) true else null,
                    roles = declaration.roles,
                    contentKind = declaration.contentKind,
                )
            },
            unresolvedEntityIds = emptyList(),
        )
        tree.resolve("source_tree_manifest.json").writeText(manifest.toJson())
    }

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun assertRejectedWithoutMarker(response: Response) {
        assertTrue(response.status in 400..499, "unsafe path returned ${response.status}")
        assertTrue(!response.body.decodeToString().contains("outside-boundary-marker"))
    }

    private fun sparseFile(path: Path, size: Long) {
        FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
            channel.position(size - 1)
            channel.write(ByteBuffer.wrap(byteArrayOf(0)))
        }
    }

    private fun withServer(
        analyzer: JobAnalyzer = JobAnalyzer { _, _ -> },
        reconstructor: JobReconstructor = JobReconstructor { _, _ -> },
        profiles: List<ReconstructionProfile> = listOf(GeneratedCMakeReconstructionProfile.descriptor),
        block: (UploadServer, java.nio.file.Path) -> Unit,
    ) {
        val dataDir = createTempDirectory("web-jobs-")
        val directExecutor = Executor { command -> command.run() }
        val server = UploadServer("127.0.0.1", 0, dataDir, analyzer, reconstructor, directExecutor, sourceProfiles = profiles)
        server.start()
        try {
            block(server, dataDir)
        } finally {
            server.stop(0)
        }
    }

    private fun upload(server: UploadServer, filename: String, content: ByteArray, acceptJson: Boolean): Response {
        val boundary = "----decomp-engine-test-boundary"
        val body = buildList<ByteArray> {
            add("--$boundary\r\n".toByteArray())
            add("Content-Disposition: form-data; name=\"binary\"; filename=\"$filename\"\r\n".toByteArray())
            add("Content-Type: application/x-elf\r\n\r\n".toByteArray())
            add(content)
            add("\r\n--$boundary--\r\n".toByteArray())
        }.fold(ByteArray(0)) { acc, bytes -> acc + bytes }
        return request(
            server,
            "POST",
            "/jobs",
            body,
            mapOf(
                "Content-Type" to "multipart/form-data; boundary=$boundary",
                "Accept" to if (acceptJson) "application/json" else "*/*",
            ),
        )
    }

    private fun request(
        server: UploadServer,
        method: String,
        path: String,
        body: ByteArray = ByteArray(0),
        headers: Map<String, String> = emptyMap(),
        followRedirects: Boolean = true,
    ): Response {
        val connection = URI("http://127.0.0.1:${server.serverPort}$path").toURL().openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.instanceFollowRedirects = followRedirects
        headers.forEach { (key, value) -> connection.setRequestProperty(key, value) }
        if (body.isNotEmpty()) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body) }
        }
        val status = connection.responseCode
        val stream = if (status >= 400) connection.errorStream else connection.inputStream
        return Response(status, stream?.readBytes() ?: ByteArray(0), connection.getHeaderField("Retry-After"), connection.getHeaderField("ETag"), connection.getHeaderField("Content-Type"), connection.getHeaderField("Cache-Control"), connection.getHeaderField("X-Request-ID"), connection.getHeaderField("Allow"))
    }

    private data class Response(val status: Int, val body: ByteArray, val retryAfter: String? = null, val etag: String? = null, val contentType: String? = null, val cacheControl: String? = null, val requestId: String? = null, val allow: String? = null)
}

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
