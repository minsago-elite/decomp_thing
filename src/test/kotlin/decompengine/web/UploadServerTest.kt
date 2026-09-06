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
            assertTrue(invalid.body.decodeToString().contains("[redacted]"))
            val uploaded = upload(server, "diagnostic.elf", elfFixture(), acceptJson = true)
            val id = Json.parseToJsonElement(uploaded.body.decodeToString()).jsonObject["id"].toString().trim('"')
            assertEquals(303, request(server, "POST", "/jobs/$id/explore", followRedirects = false).status)
            val persisted = dataDir.resolve(id).resolve("job.json").readBytes().decodeToString()
            val api = request(server, "GET", "/api/jobs/$id").body.decodeToString()
            val page = request(server, "GET", "/jobs/$id").body.decodeToString()
            listOf(persisted, api, page).forEach { text ->
                listOf(configured, bearer, password).forEach { assertTrue(!text.contains(it)) }
                assertTrue(text.contains("[redacted]"))
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
            assertTrue(html.contains("Exploration heuristic"))
            assertTrue(html.contains("0.625"))
            assertTrue(html.contains("Uncalibrated"))
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
            assertTrue(page.body.decodeToString().contains("0.750 heuristic"))
            assertTrue(page.body.decodeToString().contains("2 / 4 modules"))
            assertTrue(!page.body.decodeToString().contains("Download verified source archive"))
            assertEquals(200, source.status)
            assertTrue(source.body.decodeToString().contains("&lt;script&gt;"))
            assertTrue(!source.body.decodeToString().contains("<script>alert"))
            assertTrue(source.body.decodeToString().contains("fn_1000"))
            assertTrue(source.body.decodeToString().contains("0.800 · uncalibrated"))
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
        val server = UploadServer("127.0.0.1", 0, dataDir, analyzer, reconstructor, directExecutor, profiles)
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
        return Response(status, stream?.readBytes() ?: ByteArray(0), connection.getHeaderField("Retry-After"), connection.getHeaderField("ETag"))
    }

    private data class Response(val status: Int, val body: ByteArray, val retryAfter: String? = null, val etag: String? = null)
}

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
