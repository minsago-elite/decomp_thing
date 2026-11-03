package decompengine.web

import decompengine.jobs.*
import kotlinx.serialization.json.*
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.createTempDirectory
import kotlin.test.*

/**
 * Report families (exploration report, progress journal) leave the v1 content route only through the shared redacted
 * report projection, while their catalog identity stays the stored-bytes commitment. Synthetic bytes; no workflow runs.
 */
class WebArtifactReportProjectionTest {
    private val client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    private val octets = "application/octet-stream"
    private val canary = "decomp-report-canary-7f3a9c2e1b"
    // A configured literal made of JSON punctuation survives structural redaction; the whole document is withheld.
    private val punctuation = "\"punct1\":\""

    private class Fixture(val server: UploadServer, val root: Path, val jobId: String, val runId: String, val session: Map<String, String>) {
        val reports: Path = root.resolve(jobId).resolve("reports/runs/$runId")
        val api = "/api/v1/jobs/$jobId"
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-report-projection").toAbsolutePath())
        val root = createTempDirectory(parent, "projection-")
        val store = JobStore(root)
        val job = store.createFromUpload("inert.elf", elfFixture())
        val run = WorkflowAttemptStore.open(root).use { owner ->
            val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
            owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT, WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
        }
        Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}"))
        val server = UploadServer("127.0.0.1", 0, root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") }, uiMode = WebUiMode.SPA,
            sensitiveValues = listOf(canary), redactionEnvironment = mapOf("DECOMP_TEST_API_TOKEN" to canary, "DECOMP_PUNCT_TOKEN" to punctuation))
        server.start()
        try {
            val origin = "http://127.0.0.1:${server.serverPort}"
            val session = client.send(HttpRequest.newBuilder(URI("$origin/api/v1/session")).header("Origin", origin)
                .header("Content-Type", "application/json").header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"token\":\"${server.issueBrowserBootstrap().token}\"}")).build(), HttpResponse.BodyHandlers.ofString())
            assertEquals(200, session.statusCode())
            block(Fixture(server, root, job.id, run.runId, mapOf("Cookie" to session.headers().firstValue("Set-Cookie").orElseThrow().substringBefore(';'))))
        }
        finally { server.stop(); root.toFile().deleteRecursively() }
    }

    private fun get(fixture: Fixture, path: String, accept: String = "application/json", headers: Map<String, String> = emptyMap(), method: String = "GET"): HttpResponse<ByteArray> {
        val request = HttpRequest.newBuilder(URI("http://127.0.0.1:${fixture.server.serverPort}$path")).timeout(Duration.ofSeconds(30))
            .header("Accept", accept).header("Cookie", fixture.session.getValue("Cookie"))
        headers.forEach { (key, value) -> request.header(key, value) }
        return client.send(request.method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofByteArray())
    }

    /** The legacy report route, served by a legacy-mode listener over the same store and redaction configuration. */
    private fun legacyDownload(fixture: Fixture, name: String): HttpResponse<ByteArray> {
        fixture.server.stop()
        val legacy = UploadServer("127.0.0.1", 0, fixture.root, JobAnalyzer { _, _ -> error("unexpected analysis") },
            JobReconstructor { _, _ -> error("unexpected reconstruction") },
            sensitiveValues = listOf(canary), redactionEnvironment = mapOf("DECOMP_TEST_API_TOKEN" to canary, "DECOMP_PUNCT_TOKEN" to punctuation))
        legacy.start()
        try {
            return client.send(HttpRequest.newBuilder(URI("http://127.0.0.1:${legacy.serverPort}/jobs/${fixture.jobId}/artifacts/reports/runs/${fixture.runId}/$name"))
                .apply { legacySessionHeaders(legacy).forEach { (k, v) -> header(k, v) } }.GET().build(), HttpResponse.BodyHandlers.ofByteArray())
        } finally { legacy.stop() }
    }

    private fun json(response: HttpResponse<ByteArray>): JsonObject = Json.parseToJsonElement(String(response.body())).jsonObject
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun header(response: HttpResponse<*>, name: String) = response.headers().firstValue(name).orElse(null)

    private fun catalog(fixture: Fixture): Map<String, JsonObject> {
        val response = get(fixture, "${fixture.api}/artifacts?runId=${fixture.runId}")
        assertEquals(200, response.statusCode(), String(response.body()))
        return json(response).getValue("data").jsonObject.getValue("items").jsonArray.associate {
            it.jsonObject.getValue("family").jsonPrimitive.content to it.jsonObject
        }
    }

    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.projection() = getValue("content").jsonObject.text("projection")

    private fun assertError(response: HttpResponse<ByteArray>, status: Int, code: String) {
        assertEquals(status, response.statusCode(), String(response.body()))
        val error = json(response).getValue("error").jsonObject
        assertEquals(code, error.text("code"))
        assertEquals(false, error.getValue("retryable").jsonPrimitive.boolean)
    }

    private fun privateReport(fixture: Fixture): ByteArray = buildJsonObject {
        put("summary", "explored with $canary")
        put("workdir", fixture.root.resolve("private/work").toString())
        put("apiKey", "public-looking-value")
        put("cases", buildJsonArray { repeat(8) { add("case $it") } })
    }.toString().toByteArray()

    @Test fun `report content serves the redacted projection under projected validators while identity stays the stored commitment`() = withFixture { fixture ->
        val stored = privateReport(fixture)
        Files.write(fixture.reports.resolve("exploration.json"), stored)
        val item = catalog(fixture).getValue("exploration-report")
        assertEquals(sha256(stored), item.text("sha256"))
        assertEquals(stored.size.toString(), item.text("sizeBytes"))
        assertEquals("redacted", item.projection())
        val id = item.text("artifactId"); val href = item.text("contentHref")
        assertTrue(id.endsWith("_${sha256(stored)}"))
        assertEquals(item, json(get(fixture, href.removeSuffix("/content"))).getValue("data").jsonObject)

        val full = get(fixture, href, octets)
        assertEquals(200, full.statusCode())
        val served = full.body(); val text = String(served)
        assertFalse(text.contains(canary) || text.contains(fixture.root.toString()) || text.contains("public-looking-value"), text)
        assertEquals("[redacted]", Json.parseToJsonElement(text).jsonObject.text("apiKey"))
        val etag = "\"${sha256(served)}\""
        assertNotEquals("\"${sha256(stored)}\"", etag)
        assertEquals(etag, header(full, "ETag"))
        assertEquals(sha256(served), header(full, "X-Decomp-Content-SHA256"))
        assertEquals(sha256(stored), header(full, "X-Decomp-Artifact-SHA256"))
        assertEquals(id, header(full, "X-Decomp-Artifact-ID"))
        assertEquals("redacted", header(full, "X-Decomp-Content-Projection"))
        assertEquals(served.size.toString(), header(full, "Content-Length"))

        // Ranges, suffixes, If-Range and preconditions all describe the projected representation.
        val first = get(fixture, href, octets, mapOf("Range" to "bytes=0-9"))
        assertEquals(206, first.statusCode()); assertContentEquals(served.copyOfRange(0, 10), first.body())
        assertEquals("bytes 0-9/${served.size}", header(first, "Content-Range"))
        val suffix = get(fixture, href, octets, mapOf("Range" to "bytes=-7"))
        assertEquals(206, suffix.statusCode()); assertContentEquals(served.copyOfRange(served.size - 7, served.size), suffix.body())
        val resumed = get(fixture, href, octets, mapOf("Range" to "bytes=5-", "If-Range" to etag))
        assertEquals(206, resumed.statusCode()); assertContentEquals(served.copyOfRange(5, served.size), resumed.body())
        // The stored digest is not this representation's validator: no mixed-representation slice.
        val mixed = get(fixture, href, octets, mapOf("Range" to "bytes=0-9", "If-Range" to "\"${sha256(stored)}\""))
        assertEquals(200, mixed.statusCode()); assertContentEquals(served, mixed.body())
        val unsatisfiable = get(fixture, href, octets, mapOf("Range" to "bytes=${served.size}-"))
        assertEquals(416, unsatisfiable.statusCode()); assertEquals("bytes */${served.size}", header(unsatisfiable, "Content-Range"))
        val head = get(fixture, href, octets, method = "HEAD")
        assertEquals(200, head.statusCode()); assertEquals(0, head.body().size)
        assertEquals(served.size.toString(), header(head, "Content-Length")); assertEquals(etag, header(head, "ETag"))
        assertEquals(304, get(fixture, href, octets, mapOf("If-None-Match" to etag)).statusCode())
        assertEquals(304, get(fixture, href, octets, mapOf("If-None-Match" to "W/$etag"), "HEAD").statusCode())
        assertEquals(200, get(fixture, href, octets, mapOf("If-None-Match" to "\"${sha256(stored)}\"")).statusCode())
        assertEquals(412, get(fixture, href, octets, mapOf("If-Match" to "\"${sha256(stored)}\"")).statusCode())
        assertEquals(200, get(fixture, href, octets, mapOf("If-Match" to etag), "HEAD").statusCode())

        // Join control: the legacy report route serves exactly the same projection.
        val legacy = legacyDownload(fixture, "exploration.json")
        assertEquals(200, legacy.statusCode()); assertContentEquals(served, legacy.body())
    }

    @Test fun `clean reports stay byte identical and empty or punctuation-literal reports are honest`() = withFixture { fixture ->
        val clean = "{\"summary\":\"inert\",\"cases\":[1,2,3]}".toByteArray()
        val file = fixture.reports.resolve("exploration.json")
        Files.write(file, clean)
        val href = catalog(fixture).getValue("exploration-report").text("contentHref")
        val full = get(fixture, href, octets)
        assertEquals(200, full.statusCode()); assertContentEquals(clean, full.body())
        assertEquals("\"${sha256(clean)}\"", header(full, "ETag"))
        assertEquals(sha256(clean), header(full, "X-Decomp-Content-SHA256"))
        assertEquals(sha256(clean), header(full, "X-Decomp-Artifact-SHA256"))

        Files.write(file, "{\"punct1\":\"value\"}".toByteArray())
        val withheld = get(fixture, catalog(fixture).getValue("exploration-report").text("contentHref"), octets)
        assertEquals(200, withheld.statusCode()); assertEquals("null", String(withheld.body()))
        assertEquals("\"${sha256("null".toByteArray())}\"", header(withheld, "ETag"))

        Files.write(file, ByteArray(0))
        val emptyHref = catalog(fixture).getValue("exploration-report").text("contentHref")
        val empty = get(fixture, emptyHref, octets)
        assertEquals(200, empty.statusCode()); assertEquals(0, empty.body().size)
        assertEquals("0", header(empty, "Content-Length")); assertEquals("\"${sha256(ByteArray(0))}\"", header(empty, "ETag"))
        assertEquals(416, get(fixture, emptyHref, octets, mapOf("Range" to "bytes=0-")).statusCode())
    }

    @Test fun `changes, hard links and progress failures refuse before any projected or raw byte`() = withFixture { fixture ->
        val file = fixture.reports.resolve("exploration.json")
        Files.write(file, privateReport(fixture))
        val href = catalog(fixture).getValue("exploration-report").text("contentHref")
        Files.write(file, privateReport(fixture) + " ".toByteArray())
        val changed = get(fixture, href, octets)
        assertError(changed, 409, "ARTIFACT_CHANGED")
        assertNull(header(changed, "ETag")); assertFalse(String(changed.body()).contains(canary))

        val current = catalog(fixture).getValue("exploration-report").text("contentHref")
        Files.createLink(fixture.reports.resolve("exploration-alias.json"), file)
        val linked = get(fixture, current, octets)
        assertNotEquals(200, linked.statusCode())
        assertNull(header(linked, "ETag")); assertFalse(String(linked.body()).contains(canary))
        Files.delete(fixture.reports.resolve("exploration-alias.json"))

        // A malformed journal cannot be projected: typed refusal, never the raw journal.
        val journal = fixture.reports.resolve(AgentProgressJournal.FILE_NAME)
        Files.writeString(journal, "private broken journal $canary")
        val broken = catalog(fixture).getValue("progress-journal")
        assertEquals("redacted", broken.projection())
        val refused = get(fixture, broken.text("contentHref"), octets)
        assertError(refused, 409, "ARTIFACT_PROJECTION_UNAVAILABLE")
        assertNull(header(refused, "ETag")); assertFalse(String(refused.body()).contains(canary) || String(refused.body()).contains("broken"))

        // Over the journal read limit: the descriptor stays listed as unavailable and content is refused.
        Files.write(journal, ByteArray(AgentProgressJournal.MAXIMUM_READ_BYTES + 1) { 'a'.code.toByte() })
        val large = catalog(fixture).getValue("progress-journal")
        assertEquals("unavailable", large.projection())
        for (method in listOf("GET", "HEAD")) {
            val response = get(fixture, large.text("contentHref"), octets, method = method)
            assertEquals(409, response.statusCode()); assertNull(header(response, "ETag")); assertNull(header(response, "Content-Range"))
        }
        assertError(get(fixture, large.text("contentHref"), octets), 409, "ARTIFACT_PROJECTION_UNAVAILABLE")
    }

    @Test fun `progress journals serve their display projection with the same bytes as the legacy route`() = withFixture { fixture ->
        val journal = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 6)
            put("queueDropped", 2); put("historyDropped", 1); put("truncated", true)
            put("omittedSequenceRanges", buildJsonArray {
                for ((start, end) in listOf(0 to 1, 3 to 4, 5 to 6)) add(buildJsonObject {
                    put("startInclusive", start.toString()); put("endExclusive", end.toString())
                })
            })
            put("PRIVATE_ROOT_FIELD", "PRIVATE_ROOT_VALUE $canary")
            put("events", buildJsonArray {
                add(buildJsonObject {
                    put("sequence", 1); put("kind", "message"); put("workflow", "repair"); put("runId", "writer-1")
                    put("text", "Authorization: [redacted] PRIVATE_TAIL ${fixture.root}"); put("textOmitted", false)
                    put("workflowRunId", "PRIVATE_RUN"); put("workflowRunIdSha256", "a".repeat(64))
                })
                add(buildJsonObject {
                    put("sequence", 2); put("kind", "plan"); put("entryCount", 1); put("entriesTruncated", false)
                    put("entries", buildJsonArray { add(buildJsonObject { put("text", "PRIVATE_PLAN") }) })
                })
                add(buildJsonObject { put("sequence", 4); put("kind", "agent_finished"); put("stopReason", "completed"); put("validationPending", true) })
            })
        }.toString().toByteArray()
        Files.write(fixture.reports.resolve(AgentProgressJournal.FILE_NAME), journal)
        val item = catalog(fixture).getValue("progress-journal")
        assertEquals(sha256(journal), item.text("sha256")); assertEquals("redacted", item.projection())
        val response = get(fixture, item.text("contentHref"), octets)
        assertEquals(200, response.statusCode(), String(response.body()))
        val text = String(response.body())
        for (secret in listOf("PRIVATE", canary, fixture.root.toString())) assertFalse(text.contains(secret), text)
        assertEquals(sha256(response.body()), header(response, "X-Decomp-Content-SHA256"))
        assertEquals(sha256(journal), header(response, "X-Decomp-Artifact-SHA256"))
        val legacy = legacyDownload(fixture, AgentProgressJournal.FILE_NAME)
        assertEquals(200, legacy.statusCode()); assertContentEquals(response.body(), legacy.body())
    }

    @Test fun `source families stay verbatim job content even when they contain report-like secrets`() = withFixture { fixture ->
        val content = privateReport(fixture)
        Files.createDirectories(fixture.reports.resolve("source-tree/reports"))
        Files.write(fixture.reports.resolve("source-tree/source_tree_manifest.json"), content)
        Files.write(fixture.reports.resolve("source-tree/reports/build_contract.json"), content)
        Files.write(fixture.reports.resolve("source-tree.zip"), content)
        val items = catalog(fixture)
        for (family in listOf("source-manifest", "build-contract", "source-archive")) {
            val item = items.getValue(family)
            assertEquals("verbatim", item.projection())
            val response = get(fixture, item.text("contentHref"), octets)
            assertEquals(200, response.statusCode()); assertContentEquals(content, response.body())
            assertEquals("\"${sha256(content)}\"", header(response, "ETag"))
            assertEquals(sha256(content), header(response, "X-Decomp-Content-SHA256"))
            assertEquals(sha256(content), header(response, "X-Decomp-Artifact-SHA256"))
            assertEquals("verbatim", header(response, "X-Decomp-Content-Projection"))
        }
    }

    @Test fun `descriptor projection state follows family and the shared projection limit`() {
        assertEquals("redacted", WebReportProjection.state(WebArtifactFamily.EXPLORATION, WebReportProjection.MAXIMUM_REPORT_BYTES))
        assertEquals("unavailable", WebReportProjection.state(WebArtifactFamily.EXPLORATION, WebReportProjection.MAXIMUM_REPORT_BYTES + 1))
        assertEquals("unavailable", WebReportProjection.state(WebArtifactFamily.PROGRESS, AgentProgressJournal.MAXIMUM_READ_BYTES + 1L))
        for (family in listOf(WebArtifactFamily.MANIFEST, WebArtifactFamily.CONTRACT, WebArtifactFamily.ARCHIVE)) {
            assertEquals("verbatim", WebReportProjection.state(family, Long.MAX_VALUE))
        }
        assertTrue(WebReportProjection.MAXIMUM_REPORT_BYTES <= 64L * 1024 * 1024)
    }
}
