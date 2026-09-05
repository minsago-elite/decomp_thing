package decompengine.web

import decompengine.jobs.elfFixture
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import java.net.HttpURLConnection
import java.net.URI
import java.util.concurrent.Executor
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UploadServerTest {
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
            assertTrue(html.contains("63%"))
            assertTrue(html.contains("angr_secret"))
            assertTrue(html.contains("ARG_SECRET↵"))
            assertTrue(html.contains("Artifacts"))
            assertEquals(200, artifact.status)
            assertTrue(artifact.body.decodeToString().contains("\"candidateCount\": 2"))
        }
    }

    @Test
    fun `GUI launches reconstruction browses escaped source and downloads archive`() {
        val reconstructor = JobReconstructor { job, reportsDir ->
            assertEquals("analyzing", job.status)
            val tree = reportsDir.resolve("source-tree")
            tree.resolve("src/modules").createDirectories()
            tree.resolve("reports").createDirectories()
            tree.resolve("src/modules/core.c").writeText("int core(void) { /* <script>alert(1)</script> */ return 0; }\n")
            tree.resolve("Makefile").writeText("all:\n\t@true\n")
            tree.resolve("source_tree_manifest.json").writeText("{\"files\":[{\"path\":\"src/modules/core.c\",\"generator\":\"llm\",\"entityIds\":[\"fn_1000\"]}]}")
            tree.resolve("reports/confidence.json").writeText("{\"projectScore\":0.75,\"modules\":[{\"id\":\"core\",\"score\":0.8}]}")
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
            assertEquals(200, source.status)
            assertTrue(source.body.decodeToString().contains("&lt;script&gt;"))
            assertTrue(!source.body.decodeToString().contains("<script>alert"))
            assertTrue(source.body.decodeToString().contains("fn_1000"))
            assertTrue(source.body.decodeToString().contains("80%"))
            assertEquals("archive", archive.body.decodeToString())
            assertEquals(400, traversal.status)
        }
    }

    private fun withServer(
        analyzer: JobAnalyzer = JobAnalyzer { _, _ -> },
        reconstructor: JobReconstructor = JobReconstructor { _, _ -> },
        block: (UploadServer, java.nio.file.Path) -> Unit,
    ) {
        val dataDir = createTempDirectory("web-jobs-")
        val directExecutor = Executor { command -> command.run() }
        val server = UploadServer("127.0.0.1", 0, dataDir, analyzer, reconstructor, directExecutor)
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
        return Response(status, stream?.readBytes() ?: ByteArray(0))
    }

    private data class Response(val status: Int, val body: ByteArray)
}

private fun ByteArray.startsWith(prefix: ByteArray): Boolean =
    size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
